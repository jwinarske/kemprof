// Copyright (c) 2023 Joel Winarske
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <iomanip>

#include <cassert>
#include <csignal>

#include <libusb.h>
#include <vector>
#include <map>

#include "hexdump.h"
#include "packets.h"
#include "circular_buffer.h"

#define USB_VENDOR_ID       0x133e
#define USB_PRODUCT_ID      0x0001

#define CONFIGURATION       0x01
#define ALT_SETTING         0x00

static constexpr int MAX_PKT_LEN = 1024;

#define ERR_EXIT(errcode) do { fprintf(stderr, "   %s\n", libusb_strerror((enum libusb_error)errcode)); return -1; } while (0)
#define CALL_CHECK_CLOSE(fcall, hdl) do { int _r=fcall; if (_r < 0) { libusb_close(hdl); ERR_EXIT(_r); } } while (0)

typedef void (*PFN_TRANSFER_COMPLETE_CB)(struct libusb_transfer *xfr);

static unsigned long num_bytes[2] = {}, num_xfer[2] = {};

volatile bool g_running = true;

bool g_big_endian;

CircularBuffer<uint32_t, 1024> g_rx_buf;

std::vector<uint8_t> g_sysex_pkt;

std::map<uint32_t, std::vector<int>> g_values_int;
std::map<uint32_t, std::string> g_values_string;

void SignalHandler(int signal) {
    (void) signal;
    std::cout << std::endl << "Ctl+C" << std::endl;
    g_running = false;
}

static int LIBUSB_CALL
hotplug_callback_detach(libusb_context *ctx, libusb_device *dev, libusb_hotplug_event event, void *user_data) {
    (void) ctx;
    (void) dev;
    (void) event;
    (void) user_data;
    g_running = false;
    return 0;
}

static void LIBUSB_CALL transfer_complete_callback_ep1(struct libusb_transfer *xfr) {
    if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
        if (xfr->status == LIBUSB_TRANSFER_NO_DEVICE) {
            g_running = false;
        } else {
            fprintf(stderr, "transfer status ep1: %d\n", xfr->status);
        }
        libusb_free_transfer(xfr);
        return;
    }

#if 0
        std::stringstream ss;
        ss << Hexdump(xfr->buffer, xfr->actual_length);
        printf("%02X << %s", xfr->endpoint, ss.str().c_str());
#endif

    assert((xfr->actual_length % 4) == 0);
    //TODO printf("%02X << ", xfr->endpoint);
    auto buffer = reinterpret_cast<uint32_t *>(xfr->buffer);
    for (auto i = xfr->actual_length / sizeof(uint32_t); i > 0; --i) {
        auto val = *buffer++;
        if (!g_big_endian) {
            g_rx_buf.put(htobe32(val));
            //TODO printf("%08x ", htobe32(val));
        } else {
            g_rx_buf.put(htobe32(val));
            //TODO printf("%08x ", val);
        }
    }
    //TODO printf("\n");

    num_bytes[0] += xfr->actual_length;
    num_xfer[0]++;

    if (libusb_submit_transfer(xfr) < 0) {
        fprintf(stderr, "error re-submitting URB\n");
        exit(1);
    }
}

static void LIBUSB_CALL transfer_complete_callback_ep2(struct libusb_transfer *xfr) {
    if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
        if (xfr->status == LIBUSB_TRANSFER_NO_DEVICE) {
            g_running = false;
        } else {
            fprintf(stderr, "transfer status ep2: %d\n", xfr->status);
        }
        libusb_free_transfer(xfr);
        return;
    }

    std::stringstream ss;
    ss << Hexdump(xfr->buffer, xfr->actual_length);
    //TODO printf("%02X << %s", xfr->endpoint, ss.str().c_str());

    num_bytes[1] += xfr->actual_length;
    num_xfer[1]++;

    if (libusb_submit_transfer(xfr) < 0) {
        fprintf(stderr, "error re-submitting URB\n");
        exit(1);
    }
}

static int
queue_bulk_read(libusb_device_handle *handle, uint8_t endpoint, int max_size, PFN_TRANSFER_COMPLETE_CB callback) {
    struct libusb_transfer *xfr;
    unsigned char *data;

    data = static_cast<unsigned char *>(calloc(max_size, sizeof(uint8_t)));
    xfr = libusb_alloc_transfer(0);
    if (!xfr) {
        return -1;
    }

    libusb_fill_bulk_transfer(xfr, handle, endpoint, data, max_size, callback, nullptr, 3000);

    if (libusb_submit_transfer(xfr) < 0) {
        fprintf(stderr, "error re-submitting URB\n");
        // Error
        free(data);
        libusb_free_transfer(xfr);
    }

    return 0;
}

static int queue_bulk_write(libusb_device_handle *handle, uint8_t endpoint, unsigned char *data, int length,
                            PFN_TRANSFER_COMPLETE_CB callback) {
    struct libusb_transfer *xfr;
    xfr = libusb_alloc_transfer(0);
    if (!xfr) {
        return -1;
    }

    if (endpoint == 1) {
        assert((length % 4) == 0);
        printf("%02X >> ", endpoint);
        auto buffer = reinterpret_cast<uint32_t *>(data);
        for (auto i = length / sizeof(uint32_t); i > 0; --i) {
            if (!g_big_endian) {
                printf("%08x ", htobe32(*buffer++));
            } else {
                printf("%08x ", *buffer++);
            }
        }
        printf("\n");
    } else {
#if 0
        printf("[0x%02X] length:%u\n", endpoint, length);
        std::stringstream ss;
        ss << Hexdump(data, length);
        printf("%02X >> %s\n", endpoint, ss.str().c_str());
#endif
    }

    libusb_fill_bulk_transfer(xfr, handle, endpoint, data, length, callback, handle, 3000);

    if (libusb_submit_transfer(xfr) < 0) {
        // Error
        //free(data);
        libusb_free_transfer(xfr);
    }

    return 0;
}

static void LIBUSB_CALL write_complete_callback(struct libusb_transfer *xfr) {
    static int msg_ep1 = 0, msg_ep2 = 0;

    if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
        fprintf(stderr, "write_complete_callback: %d\n", xfr->status);
        libusb_free_transfer(xfr);
        return;
    }

    auto handle = reinterpret_cast<libusb_device_handle *>(xfr->user_data);

    if (xfr->endpoint == 0x01) {
        auto idx = ++msg_ep1;
        if (idx < 36) {
            queue_bulk_write(handle, 0x01, msg[0][idx].msg, msg[0][idx].size, write_complete_callback);
        }
    } else if (xfr->endpoint == 0x02) {
        auto idx = ++msg_ep2;
        if (idx < 12) {
            queue_bulk_write(handle, 0x02, msg[1][idx].msg, msg[1][idx].size, write_complete_callback);
        }
    }

    libusb_free_transfer(xfr);
}

int32_t decode_int32(const uint8_t *inp) {
    int32_t res = 0;
    for (int i = 0; i < 5; i++) {
        res <<= 7;
        res |= *inp++ & 0x7f;
    }
    return res;
}

uint32_t decode_uint32(const uint8_t *inp) {
    uint32_t res = 0;
    for (int i = 0; i < 5; i++) {
        res <<= 7;
        res |= *inp++ & 0x7f;
    }
    return res;
}

int16_t decode_int16(const uint8_t *inp) {
    int16_t res = 0;
    for (int i = 0; i < 2; i++) {
        res <<= 7;
        res |= *inp++ & 0x7fU;
    }
    return res;
}

uint16_t decode_uint16(const uint8_t *inp) {
    uint16_t res = 0;
    for (int i = 0; i < 2; i++) {
        res <<= 7;
        res |= *inp++ & 0x7f;
    }
    return res;
}

void parse_fb(uint32_t val) {
    printf("\n+++++++++++++++++++\n");
    printf("%04x\n", val);
    printf("+++++++++++++++++++\n");
}

std::vector<uint8_t> expand7bit(const uint8_t *data, int len) {

    std::vector<uint8_t> res(len);

    int begin = 0;
    int end = len - 1;

    int shift = 1;
    int j = 0;
    for (; begin + j < end - 1; j++) {
        res[j] = ((data[begin + j] & 0xFF) << shift) +
                 static_cast<int>(
                         static_cast<unsigned int>((data[begin + j + 1] & 0xFF)) >> (7 - shift));
        shift++;
        if (shift == 8) {
            shift = 1;
            begin++;
        }
    }
    res[j] = data[len - 1] & 0xFF << shift;

    res.resize(j + 1);

    return res;
}

std::vector<int32_t> get_values(const uint8_t *data, uint64_t len) {
    assert((len % 2) == 0);
    auto count = len / 2;

    std::vector<int32_t> res(count);
    for (; count > 0; --count) {
        res.push_back(decode_int16(data));
        data += 2;
    }
    return res;
}

std::vector<int32_t> get_extended_values(const uint8_t *data, uint64_t len) {
    assert((len % 5) == 0);
    auto count = len / 5;
    std::vector<int32_t> res(count);
    for (; count > 0; --count) {
        res.push_back(decode_int32(data));
        data += 5;
    }
    return res;
}

void parse_sys_ex(std::vector<uint8_t> &pkt) {
    auto buff = pkt.data();

#if 0
    std::stringstream ss;
    ss << Hexdump(buff, pkt.size());
    printf("\n%s", ss.str().c_str());
#endif

    // Confirm we're a valid SysEx packet
    assert(buff[0] == SYX);
    assert(buff[1] == 0x00);
    assert(buff[2] == 0x20);
    assert(buff[3] == 0x33);
    assert(buff[pkt.size() - 1] == EOX);
    auto function_code = buff[6];

    printf("********************************\n");
    printf("Product Type ... ");
    switch (buff[4]) {
        case 0x00: {
            printf("Kemper Profiler\n");
            break;
        }
        default: {
            printf("%d\n", buff[4]);
            break;
        }
    }
    printf("Device ID ...... %02x\n", buff[5]);
    printf("Function Code .. ");
    switch (function_code) {
        case FunctionCode::REQ_SINGLE_PARAMETER_CHANGE:
            printf("REQ_");
        case FunctionCode::SINGLE_PARAMETER_CHANGE: {
            printf("SINGLE_PARAMETER_CHANGE\n");
            assert(buff[7] == 0x00);
            auto controller = decode_uint16(&buff[8]);
            printf("Controller ..... %d\n", controller);

            if (function_code == REQ_SINGLE_PARAMETER_CHANGE)
                return;

            auto value = decode_int16(&buff[10]);
            g_values_int[controller].reserve(1);
            g_values_int[controller].push_back(value);

            printf("Value .......... %d\n", g_values_int[controller][0]);
            break;
        }
        case FunctionCode::REQ_MULTI_PARAMETER_CHANGE:
            printf("REQ_");
        case FunctionCode::MULTI_PARAMETER_CHANGE: {
            printf("MULTI_PARAMETER_CHANGE\n");
            assert(buff[7] == 0x00);
            auto controller = decode_uint16(&buff[8]);
            printf("Controller ..... %d\n", controller);

            if (function_code == REQ_MULTI_PARAMETER_CHANGE)
                return;

            auto values = get_values(&buff[10], pkt.size() - 11);
            g_values_int[controller] = std::move(values);

            printf("Count .......... %zu\n", g_values_int[controller].size());
            for (auto const &value: g_values_int[controller]) {
                printf("Value .......... %d\n", value);
            }
            break;
        }
        case FunctionCode::REQ_STRING_PARAMETER_CHANGE:
            printf("REQ_");
        case FunctionCode::STRING_PARAMETER: {
            printf("STRING_PARAMETER\n");
            assert(buff[7] == 0x00);
            auto controller = decode_uint16(&buff[8]);
            printf("Controller ..... %d\n", controller);

            if (function_code == REQ_STRING_PARAMETER_CHANGE)
                return;

            if (controller) {
                g_values_string[controller] = std::string(reinterpret_cast<const char *>(&buff[10]));
                printf("Value .......... [%s]\n", g_values_string[controller].c_str());
            }
            break;
        }
        case FunctionCode::BLOB: {
            printf("BLOB\n");
            assert(buff[7] == 0x00);
            auto controller = decode_uint16(&buff[8]);
            auto start = decode_uint16(&buff[10]);
            auto size = decode_uint16(&buff[12]);

            printf("Controller ..... %d\n", controller);
            printf("Start .......... %d\n", start);
            printf("Size ........... %d\n", size);
            assert(size == (pkt.size() - 15));
            auto blob = expand7bit(&buff[14], size);
            printf("8-bit Size ..... %zu\n", blob.size());
            std::stringstream ss;
            ss << Hexdump(blob.data(), blob.size());
            printf("%s", ss.str().c_str());
            break;
        }
        case FunctionCode::EXTENDED_PARAMETER_CHANGE: {
            printf("EXTENDED_PARAMETER_CHANGE\n");
            assert(buff[7] == 0x00);

            auto controller = decode_uint32(&buff[8]);
            auto values = get_extended_values(&buff[13], pkt.size() - 14);
            g_values_int[controller] = std::move(values);

            printf("Controller ..... %d\n", controller);
            printf("Count .......... %zu\n", g_values_int[controller].size());
            for (auto const &value: g_values_int[controller]) {
                printf("Value .......... %d\n", value);
            }
            break;
        }
        case FunctionCode::MORPHED_MULTI_PARAMETER_CHANGED: {
            printf("MORPHED_MULTI_PARAMETER_CHANGED\n");
            std::stringstream ss;
            ss << Hexdump(buff, pkt.size());
            printf("\n%s", ss.str().c_str());
            break;
        }
        case FunctionCode::EXTENDED_STRING_PARAMETER_CHANGE: {
            printf("EXTENDED_STRING_PARAMETER_CHANGE\n");
            assert(buff[7] == 0x00);
            auto controller = decode_uint32(&buff[8]);
            g_values_string[controller] = std::string(reinterpret_cast<const char *>(&buff[13]));
            printf("Controller ..... %d\n", controller);
            printf("Value .......... [%s]\n", g_values_string[controller].c_str());
            break;
        }
        case FunctionCode::REQ_PARAMETER_VALUE_AS_RENDERED_STRING: {
            printf("REQ_PARAMETER_VALUE_AS_RENDERED_STRING\n");
            std::stringstream ss;
            ss << Hexdump(buff, pkt.size());
            printf("\n%s", ss.str().c_str());
            break;
        }
        default: {
            printf("%02x\n", function_code);
            std::stringstream ss;
            ss << Hexdump(buff, pkt.size());
            printf("\n%s", ss.str().c_str());
        }
    }

    g_sysex_pkt.clear();
}

int main() {
    libusb_device_handle *handle;
    libusb_context *ctx = nullptr;
    bool debug_mode = false;
    bool extra_info = true;
    libusb_hotplug_callback_handle hp;
    int r;

    g_sysex_pkt.reserve(MAX_PKT_LEN);

    unsigned int x = 0x76543210;
    char *c = (char *) &x;
    if (*c == 0x10) {
        g_big_endian = false;
    } else {
        g_big_endian = true;
        printf("Host is Big Endian\n");
    }

    if (debug_mode) {
        static char debug_env_str[] = "LIBUSB_DEBUG=4";    // LIBUSB_LOG_LEVEL_DEBUG
        if (putenv(debug_env_str) != 0)
            std::cerr << "Unable to set debug level" << std::endl;
    }

    const struct libusb_version *version = libusb_get_version();
    std::cout << "Using libusb v" <<
              version->major << "." <<
              version->minor << "." <<
              version->micro << "." <<
              version->nano << std::endl;

    r = libusb_init(&ctx);
    if (r < 0) {
        std::cout << "libusb_init: " << libusb_strerror((enum libusb_error) r);
        return 1;
    }

    std::cout << "Opening device " << std::setfill('0') << std::setw(4) << std::right << std::hex << USB_VENDOR_ID
              << ":" << std::setfill('0') << std::setw(4) << std::right << std::hex << USB_PRODUCT_ID << std::endl;
    handle = libusb_open_device_with_vid_pid(ctx, USB_VENDOR_ID, USB_PRODUCT_ID);
    if (handle == nullptr) {
        std::cerr << "Could not open device." << std::endl;
        return 1;
    }

    libusb_device *dev = libusb_get_device(handle);
    if (extra_info) {
        uint8_t port_path[8];
        uint8_t bus = libusb_get_bus_number(dev);
        r = libusb_get_port_numbers(dev, port_path, sizeof(port_path));
        if (r > 0) {
            printf("\nDevice properties:\n");
            printf("        bus number: %d\n", bus);
            printf("        port path: %d", port_path[0]);
            for (int i = 1; i < r; i++) {
                printf("->%d", port_path[i]);
            }
            printf(" (from root hub)\n");
        }
        r = libusb_get_device_speed(dev);
        if ((r < 0) || (r > 5)) {
            r = 0;
        }
        const char *const speed_name[6] = {"Unknown", "1.5 Mbit/s (USB LowSpeed)", "12 Mbit/s (USB FullSpeed)",
                                           "480 Mbit/s (USB HighSpeed)", "5000 Mbit/s (USB SuperSpeed)",
                                           "10000 Mbit/s (USB SuperSpeedPlus)"};
        std::cout << "        speed: " << speed_name[r] << std::endl;
    }

    printf("\nDevice descriptor:\n");
    struct libusb_device_descriptor dev_desc{};
    CALL_CHECK_CLOSE(libusb_get_device_descriptor(dev, &dev_desc), handle);
    printf("            length: %d\n", dev_desc.bLength);
    printf("      device class: %d\n", dev_desc.bDeviceClass);
    printf("               S/N: %d\n", dev_desc.iSerialNumber);
    printf("           VID:PID: %04X:%04X\n", dev_desc.idVendor, dev_desc.idProduct);
    printf("         bcdDevice: %04X\n", dev_desc.bcdDevice);
    printf("          nb confs: %d\n", dev_desc.bNumConfigurations);

    printf("\nReading string descriptors:\n");
    char string[128];
    uint8_t string_index[3];    // indexes of the string descriptors
    string_index[0] = dev_desc.iManufacturer;
    string_index[1] = dev_desc.iProduct;
    string_index[2] = dev_desc.iSerialNumber;
    for (unsigned char i: string_index) {
        if (i == 0) {
            continue;
        }
        if (libusb_get_string_descriptor_ascii(handle, i, (unsigned char *) string, sizeof(string)) > 0) {
            printf("   String (0x%02X): \"%s\"\n", i, string);
        }
    }

    // vendor strings
    for (int i = 4; i <= 10; i++) {
        if (libusb_get_string_descriptor_ascii(handle, i, (unsigned char *) string, sizeof(string)) > 0) {
            printf("   String (0x%02X): \"%s\"\n", i, string);
        }
    }
    printf("\n");

    printf("\nConfiguration descriptor:\n");
    int nb_ifaces, first_iface = -1;
    struct libusb_config_descriptor *conf_desc;
    const struct libusb_endpoint_descriptor *endpoint;

    CALL_CHECK_CLOSE(libusb_get_config_descriptor(dev, 0, &conf_desc), handle);
    printf("              total length: %d\n", conf_desc->wTotalLength);
    printf("         descriptor length: %d\n", conf_desc->bLength);
    nb_ifaces = conf_desc->bNumInterfaces;
    printf("             nb interfaces: %d\n", nb_ifaces);
    if (nb_ifaces > 0)
        first_iface = conf_desc->interface[0].altsetting[0].bInterfaceNumber;
    for (int i = 0; i < nb_ifaces; i++) {
        printf("              interface[%d]: id = %d\n", i, conf_desc->interface[i].altsetting[0].bInterfaceNumber);
        for (int j = 0; j < conf_desc->interface[i].num_altsetting; j++) {
            printf("interface[%d].altsetting[%d]: num endpoints = %d\n", i, j,
                   conf_desc->interface[i].altsetting[j].bNumEndpoints);
            printf("   Class.SubClass.Protocol: %02X.%02X.%02X\n",
                   conf_desc->interface[i].altsetting[j].bInterfaceClass,
                   conf_desc->interface[i].altsetting[j].bInterfaceSubClass,
                   conf_desc->interface[i].altsetting[j].bInterfaceProtocol);
            for (int k = 0; k < conf_desc->interface[i].altsetting[j].bNumEndpoints; k++) {
                endpoint = &conf_desc->interface[i].altsetting[j].endpoint[k];
                printf("       endpoint[%d].address: %02X\n", k, endpoint->bEndpointAddress);
                printf("           max packet size: %04X\n", endpoint->wMaxPacketSize);
                printf("          polling interval: %02X\n", endpoint->bInterval);
            }
        }
    }

    printf("\n");


    if (libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        r = libusb_hotplug_register_callback(ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, 0, USB_VENDOR_ID, USB_PRODUCT_ID,
                                             LIBUSB_HOTPLUG_MATCH_ANY, hotplug_callback_detach, nullptr, &hp);
        if (LIBUSB_SUCCESS != r) {
            fprintf(stderr, "libusb_hotplug_register_callback: %s\n", libusb_strerror((enum libusb_error) r));
            libusb_close(handle);
            libusb_exit(ctx);
            return EXIT_FAILURE;
        }
    }

    if (libusb_has_capability(LIBUSB_CAP_SUPPORTS_DETACH_KERNEL_DRIVER)) {
        r = libusb_set_auto_detach_kernel_driver(handle, 1);
        if (LIBUSB_SUCCESS != r) {
            fprintf(stderr, "libusb_set_auto_detach_kernel_driver: %s\n", libusb_strerror((enum libusb_error) r));
        }
    }

    int config;
    r = libusb_get_configuration(handle, &config);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_get_configuration: %s\n", libusb_strerror((enum libusb_error) r));
    }

    if (config != CONFIGURATION) {
        r = libusb_set_configuration(handle, CONFIGURATION);
        if (LIBUSB_SUCCESS != r) {
            fprintf(stderr, "libusb_set_configuration: %s\n", libusb_strerror((enum libusb_error) r));
        }
    }
    r = libusb_get_configuration(handle, &config);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_get_configuration: %s\n", libusb_strerror((enum libusb_error) r));
    }
    std::cout << "Configuration: " << config << std::endl;

    r = libusb_claim_interface(handle, first_iface);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_claim_interface: %s\n", libusb_strerror((enum libusb_error) r));
        assert(false);
    }
    std::cout << "Interface " << first_iface << " claimed" << std::endl;
    std::cout << std::endl;

    for (int k = 0; k < conf_desc->interface[first_iface].altsetting[ALT_SETTING].bNumEndpoints; k++) {
        endpoint = &conf_desc->interface[first_iface].altsetting[ALT_SETTING].endpoint[k];
        if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) & (LIBUSB_TRANSFER_TYPE_BULK)) {
            r = libusb_clear_halt(handle, endpoint->bEndpointAddress);
            if (LIBUSB_SUCCESS != r) {
                fprintf(stderr, "libusb_clear_halt: %s\n", libusb_strerror((enum libusb_error) r));
            }
        }
    }

    for (int k = 0; k < conf_desc->interface[first_iface].altsetting[ALT_SETTING].bNumEndpoints; k++) {
        endpoint = &conf_desc->interface[first_iface].altsetting[ALT_SETTING].endpoint[k];
        if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) & (LIBUSB_TRANSFER_TYPE_BULK)) {
            if (endpoint->bEndpointAddress == 0x81) {
                for (int i = 0; i < 10; i++) {
                    queue_bulk_read(handle, endpoint->bEndpointAddress, endpoint->wMaxPacketSize,
                                    transfer_complete_callback_ep1);
                }
            } else if (endpoint->bEndpointAddress == 0x82) {
                for (int i = 0; i < 10; i++) {
                    queue_bulk_read(handle, endpoint->bEndpointAddress, endpoint->wMaxPacketSize,
                                    transfer_complete_callback_ep2);
                }
            }
        }
    }

    libusb_free_config_descriptor(conf_desc);

    std::signal(SIGINT, SignalHandler);

    queue_bulk_write(handle, 0x01, msg[0][0].msg, msg[0][0].size, write_complete_callback);
    queue_bulk_write(handle, 0x02, msg[1][0].msg, msg[1][0].size, write_complete_callback);

    while (g_running) {
        if (libusb_handle_events(nullptr) != LIBUSB_SUCCESS) break;
        while (!g_rx_buf.empty()) {

            auto val = g_rx_buf.get().value();
            uint8_t cmd = (val & 0xFF000000) >> 24U;
            switch (cmd) {
                case 0xfb: {
                    parse_fb(val);
                    break;
                }
                case 0x14: {
                    g_sysex_pkt.push_back((val & 0x00ff0000) >> 16U);
                    g_sysex_pkt.push_back((val & 0x0000ff00) >> 8U);
                    g_sysex_pkt.push_back(val & 0x000000ff);
                    //printf("%03x", val & 0x00ffffff);
                    break;
                }
                case 0x15: {
                    assert((val & 0x15f70000) == 0x15f70000);
                    g_sysex_pkt.push_back(0xf7);
                    //printf("f7\n");
                    parse_sys_ex(g_sysex_pkt);
                    break;
                }
                case 0x16: {
                    assert((val & 0x1600f700) == 0x1600f700);
                    if ((val & 0x00ff0000) == 0x00f70000) {
                        g_sysex_pkt.push_back(0xf7);
                        //printf("f7\n");
                        parse_sys_ex(g_sysex_pkt);
                    } else {
                        g_sysex_pkt.push_back((val & 0x00ff0000) >> 16U);
                        g_sysex_pkt.push_back(0xf7);
                        //printf("%02xf7\n", (val & 0x00ff0000) >> 16U);
                        parse_sys_ex(g_sysex_pkt);
                    }
                    break;
                }
                case 0x17: {
                    assert((val & 0x170000f7) == 0x170000f7);
                    if ((val & 0x00ff0000) == 0x00f70000) {
                        g_sysex_pkt.push_back(0xf7);
                        //printf("f7\n");
                        parse_sys_ex(g_sysex_pkt);
                    } else if ((val & 0x0000ff00) == 0x0000f700) {
                        g_sysex_pkt.push_back((val & 0x00ff0000) >> 16U);
                        g_sysex_pkt.push_back(0xf7);
                        //printf("%02xf7\n", (val & 0x00ff0000) >> 16U);
                        parse_sys_ex(g_sysex_pkt);
                    } else {
                        g_sysex_pkt.push_back((val & 0x0000ff00) >> 8U);
                        g_sysex_pkt.push_back((val & 0x00ff0000) >> 16U);
                        g_sysex_pkt.push_back(0xf7);
                        //printf("%04xf7\n", (val & 0x00ffff00) >> 8U);
                        parse_sys_ex(g_sysex_pkt);
                    }
                    break;
                }
                default: {
                    printf("\nUnknown: %04X\n", val);
                }
            }
        }
    }

    r = libusb_release_interface(handle, first_iface);
    if (LIBUSB_SUCCESS == r) {
        std::cout << "Interface released." << std::endl;
    }

    libusb_close(handle);
    libusb_exit(ctx);

    return 0;
}