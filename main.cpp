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

#include <libusb.h>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <csignal>

#include "hex_dump.h"
#include "packets.h"

#define USB_VENDOR_ID       0x133e
#define USB_PRODUCT_ID      0x0001

#define ALT_SETTING         0x00

#define ERR_EXIT(errcode) do { fprintf(stderr, "   %s\n", libusb_strerror((enum libusb_error)errcode)); return -1; } while (0)
#define CALL_CHECK_CLOSE(fcall, hdl) do { int _r=fcall; if (_r < 0) { libusb_close(hdl); ERR_EXIT(_r); } } while (0)

typedef void (*PFN_TRANSFER_COMPLETE_CB)(struct libusb_transfer *xfr);

static unsigned long num_bytes[2] = {}, num_xfer[2] = {};

volatile bool running = true;

void SignalHandler(int signal) {
    (void) signal;
    std::cout << std::endl << "Ctl+C" << std::endl;
    running = false;
}

static void transfer_complete_callback_ep1(struct libusb_transfer *xfr) {
    if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
        fprintf(stderr, "transfer status ep1: %d\n", xfr->status);
        libusb_free_transfer(xfr);
        return;
    }

    printf("[Rx.1] length:%u, actual_length:%u\n", xfr->length, xfr->actual_length);
    std::stringstream ss;
    ss << Hexdump(xfr->buffer, xfr->actual_length);
    printf("%s\n", ss.str().c_str());

    num_bytes[0] += xfr->actual_length;
    num_xfer[0]++;

    if (libusb_submit_transfer(xfr) < 0) {
        fprintf(stderr, "error re-submitting URB\n");
        exit(1);
    }
}

static void transfer_complete_callback_ep2(struct libusb_transfer *xfr) {
    if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
        fprintf(stderr, "transfer status ep1: %d\n", xfr->status);
        libusb_free_transfer(xfr);
        return;
    }

    printf("[Rx.2] length:%u, actual_length:%u\n", xfr->length, xfr->actual_length);
    std::stringstream ss;
    ss << Hexdump(xfr->buffer, xfr->actual_length);
    printf("%s\n", ss.str().c_str());

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

    libusb_fill_bulk_transfer(xfr, handle, endpoint, data, length, callback, handle, 3000);

    if (libusb_submit_transfer(xfr) < 0) {
        // Error
        //free(data);
        libusb_free_transfer(xfr);
    }

    return 0;
}

static void write_complete_callback(struct libusb_transfer *xfr) {
    static int msg_ep1 = 0, msg_ep2 = 0;

    if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
        fprintf(stderr, "write_complete_callback: %d\n", xfr->status);
        libusb_free_transfer(xfr);
        return;
    }

    auto handle = reinterpret_cast<libusb_device_handle *>(xfr->user_data);

    if (xfr->endpoint == 0x01) {
        auto idx = msg_ep1++;
        queue_bulk_write(handle, 0x01, msg[0][idx].msg, msg[0][idx].size, write_complete_callback);
    } else if (xfr->endpoint == 0x02) {
        auto idx = msg_ep2++;
        queue_bulk_write(handle, 0x02, msg[1][idx].msg, msg[1][idx].size, write_complete_callback);
    }

    libusb_free_transfer(xfr);
}

int main() {
    libusb_device_handle *handle;
    libusb_context *ctx = nullptr;
    bool debug_mode = false;
    bool extra_info = true;
    int r;

    if (debug_mode) {
        static char debug_env_str[] = "LIBUSB_DEBUG=4";    // LIBUSB_LOG_LEVEL_DEBUG
        if (putenv(debug_env_str) != 0)
            std::cerr << "Unable to set debug level" << std::endl;
    }

    const struct libusb_version *version = libusb_get_version();
    std::cout << "Using libusb v" << version->major << "." << version->minor << "." << version->micro << "."
              << version->nano << std::endl;

    r = libusb_setlocale("en");
    if (r < 0) {
        std::cout << "Invalid or unsupported locale 'en': " << libusb_strerror((enum libusb_error) r);
    }

    r = libusb_init(&ctx);
    if (r < 0) {
        std::cerr << "Init error." << std::endl;
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
    printf("   iMan:iProd:iSer: %d:%d:%d\n", dev_desc.iManufacturer, dev_desc.iProduct, dev_desc.iSerialNumber);
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

    printf("\nConfiguration descriptor:\n");
    int nb_ifaces, first_iface = -1;
    struct libusb_config_descriptor *conf_desc;
    const struct libusb_endpoint_descriptor *endpoint;
    uint8_t endpoint_in = 0, endpoint_out = 0;    // default IN and OUT endpoints

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
                struct libusb_ss_endpoint_companion_descriptor *ep_comp = nullptr;
                endpoint = &conf_desc->interface[i].altsetting[j].endpoint[k];
                printf("       endpoint[%d].address: %02X\n", k, endpoint->bEndpointAddress);
                // Use the first bulk IN/OUT endpoints as default
                if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) & (LIBUSB_TRANSFER_TYPE_BULK)) {
                    if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                        if (!endpoint_in)
                            endpoint_in = endpoint->bEndpointAddress;
                    } else {
                        if (!endpoint_out)
                            endpoint_out = endpoint->bEndpointAddress;
                    }
                }
                printf("           max packet size: %04X\n", endpoint->wMaxPacketSize);
                printf("          polling interval: %02X\n", endpoint->bInterval);
                libusb_get_ss_endpoint_companion_descriptor(nullptr, endpoint, &ep_comp);
                if (ep_comp) {
                    printf("                 max burst: %02X   (USB 3.0)\n", ep_comp->bMaxBurst);
                    printf("        bytes per interval: %04X (USB 3.0)\n", ep_comp->wBytesPerInterval);
                    libusb_free_ss_endpoint_companion_descriptor(ep_comp);
                }
            }
        }
    }

    unsigned char buff[255];
    r = libusb_get_descriptor(handle, LIBUSB_DT_STRING, 0x00, buff, sizeof(buff));
    if (r < 0) {
        fprintf(stderr, "libusb_get_descriptor: %s\n", libusb_strerror((enum libusb_error) r));
    }
    for (int i = 0; i < r; i++) {
        printf("%02X", buff[i]);
    }
    printf("\n");

    for (int i = 4; i <= 10; i++) {
        if (libusb_get_string_descriptor_ascii(handle, i, (unsigned char *) string, sizeof(string)) > 0) {
            printf("   String (0x%02X): \"%s\"\n", i, string);
        }
    }
    printf("\n");

    r = libusb_set_auto_detach_kernel_driver(handle, 1);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_set_auto_detach_kernel_driver: %s\n", libusb_strerror((enum libusb_error) r));
    }

    int config;
    r = libusb_get_configuration(handle, &config);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_get_configuration: %s\n", libusb_strerror((enum libusb_error) r));
    }

    if (config != 1) {
        r = libusb_set_configuration(handle, 1);
        if (LIBUSB_SUCCESS != r) {
            fprintf(stderr, "libusb_set_configuration: %s\n", libusb_strerror((enum libusb_error) r));
        }
    }
    r = libusb_get_configuration(handle, &config);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_get_configuration: %s\n", libusb_strerror((enum libusb_error) r));
    }
    printf("Configuration: %d\n", config);

    r = libusb_claim_interface(handle, first_iface);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_claim_interface: %s\n", libusb_strerror((enum libusb_error) r));
        assert(false);
    }
    std::cout << "Interface claimed." << std::endl;

    r = libusb_clear_halt(handle, 0x01);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_clear_halt: %s\n", libusb_strerror((enum libusb_error) r));
    }
    r = libusb_clear_halt(handle, 0x81);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_clear_halt: %s\n", libusb_strerror((enum libusb_error) r));
    }

    for (int k = 0; k < conf_desc->interface[first_iface].altsetting[ALT_SETTING].bNumEndpoints; k++) {
        endpoint = &conf_desc->interface[first_iface].altsetting[ALT_SETTING].endpoint[k];
        if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) & (LIBUSB_TRANSFER_TYPE_BULK)) {
            if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                if (endpoint->bEndpointAddress == 0x81) {
                    for (int i = 0; i < 10; i++) {
                        queue_bulk_read(handle, endpoint->bEndpointAddress, endpoint->wMaxPacketSize,
                                        transfer_complete_callback_ep1);
                    }
                }
            }
        }
    }

    r = libusb_clear_halt(handle, 0x02);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_clear_halt: %s\n", libusb_strerror((enum libusb_error) r));
    }
    r = libusb_clear_halt(handle, 0x82);
    if (LIBUSB_SUCCESS != r) {
        fprintf(stderr, "libusb_clear_halt: %s\n", libusb_strerror((enum libusb_error) r));
    }

    for (int k = 0; k < conf_desc->interface[first_iface].altsetting[ALT_SETTING].bNumEndpoints; k++) {
        endpoint = &conf_desc->interface[first_iface].altsetting[ALT_SETTING].endpoint[k];
        if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) & (LIBUSB_TRANSFER_TYPE_BULK)) {
            if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                if (endpoint->bEndpointAddress == 0x82) {
                    for (int i = 0; i < 10; i++) {
                        queue_bulk_read(handle, endpoint->bEndpointAddress, endpoint->wMaxPacketSize,
                                        transfer_complete_callback_ep2);
                    }
                }
            }
        }
    }

    libusb_free_config_descriptor(conf_desc);

    std::signal(SIGINT, SignalHandler);

    int msg_ep1 = 0, msg_ep2 = 0;
    queue_bulk_write(handle, 0x01, msg[0][0].msg, msg[0][0].size, write_complete_callback);
    queue_bulk_write(handle, 0x02, msg[1][0].msg, msg[1][0].size, write_complete_callback);

    while (running) {
        if (libusb_handle_events(nullptr) != LIBUSB_SUCCESS) break;
    }

    r = libusb_release_interface(handle, first_iface);
    if (r < 0) {
        std::cout << "Could not release interface." << std::endl;
        return 1;
    }
    std::cout << "Interface released." << std::endl;

    libusb_close(handle);
    libusb_exit(ctx);

    std::cout << "End of main" << std::endl;
    return 0;
}