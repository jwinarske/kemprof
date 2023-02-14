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

typedef struct {
    int size;
    unsigned char msg[64];
} MSG_T;

MSG_T msg[2][36] = {
        {
                {.size = 12, .msg = {0xfb, 0xbf, 0x7f, 0x7f, 0xfb, 0xb1, 0x7f, 0x01, 0xfb, 0xb2, 0x7f, 0x01}},
                {.size = 64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x06, 0x00, 0x00,
                                     0x14, 0x00, 0x01, 0x04, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
                                     0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f,
                                     0x14, 0x06, 0x00, 0x00, 0x14, 0x00, 0x01, 0x04, 0x14, 0x01, 0x00, 0x00,
                                     0x14, 0x00, 0x00, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20,
                                     0x14, 0x33, 0x02, 0x7f}},
                {.size=64, .msg = {0x14, 0x06, 0x00, 0x00, 0x14, 0x00, 0x01, 0x04, 0x14, 0x00, 0x00, 0x00, 0x14,
                                   0x00, 0x00, 0x01, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x02, 0x7f, 0x14, 0x06, 0x00, 0x00, 0x14, 0x00, 0x06, 0x20, 0x14, 0x00, 0x00,
                                   0x00, 0x14, 0x00, 0x00, 0x07, 0x14, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00,
                                   0x14, 0x00, 0x00, 0x0f, 0x14, 0x67, 0x00, 0x00, 0x14, 0x00, 0x00, 0x08}},
                {.size=16, .msg = {0x14, 0x00, 0x00, 0x00, 0x14, 0x00, 0x09, 0x00, 0x14, 0x00, 0x00, 0x00, 0x16,
                                   0x1c, 0xf7, 0x00}},
                {.size=20, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x47, 0x00, 0x00, 0x14,
                                   0x00, 0x0c, 0x1a, 0x16, 0x40, 0xf7, 0x00}},
                {.size=20, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x47, 0x00, 0x00, 0x14,
                                   0x00, 0x0c, 0x1a, 0x16, 0x41, 0xf7, 0x00}},
                {.size=16, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x41, 0x00, 0x7f, 0x16,
                                   0x7d, 0xf7, 0x00}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x01, 0x00, 0x7f, 0x14,
                                   0x7c, 0x00, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x02, 0x7f, 0x14, 0x03, 0x00, 0x7f, 0x14, 0x7d, 0x52, 0x69, 0x14, 0x67, 0x20,
                                   0x4d, 0x14, 0x61, 0x6e, 0x61, 0x14, 0x67, 0x65, 0x72, 0x16, 0x00, 0xf7, 0x00,
                                   0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x03, 0x00, 0x7f}},

                {.size=44, .msg = {0x14, 0x7c, 0x53, 0x79, 0x14, 0x6e, 0x63, 0x69, 0x14, 0x6e, 0x67, 0x20, 0x14,
                                   0x50, 0x72, 0x65, 0x14, 0x73, 0x65, 0x74, 0x14, 0x73, 0x2e, 0x2e, 0x17, 0x2e,
                                   0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x03, 0x00,
                                   0x7f, 0x17, 0x7b, 0x00, 0xf7}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x01, 0x00, 0x7f, 0x14,
                                   0x7c, 0x00, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x02, 0x7f, 0x14, 0x03, 0x00, 0x7f, 0x17, 0x7d, 0x00, 0xf7, 0x14, 0xf0, 0x00,
                                   0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x03, 0x00, 0x7f, 0x17, 0x7c, 0x00, 0xf7,
                                   0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x03, 0x00, 0x7f}},

                {.size=4, .msg = {0x17, 0x7b, 0x00, 0xf7}},

                {.size=28, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x7f, 0x14, 0x06, 0x00, 0x00, 0x14,
                                   0x00, 0x01, 0x04, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x15, 0xf7,
                                   0x00, 0x00}},

                {.size=56, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x00, 0x14, 0x06, 0x00, 0x00, 0x14,
                                   0x00, 0x06, 0x21, 0x14, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01, 0x15, 0xf7,
                                   0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x00, 0x14, 0x06, 0x00,
                                   0x00, 0x14, 0x00, 0x06, 0x21, 0x14, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01,
                                   0x15, 0xf7, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14,
                                   0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00,
                                   0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00,
                                   0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20}},

                {.size=16, .msg = {0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15,
                                   0xf7, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14,
                                   0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00,
                                   0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a,
                                   0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0x03, 0x00, 0x0a, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14,
                                   0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42,
                                   0x6f, 0x20, 0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20, 0x52, 0x14, 0x65, 0x63,
                                   0x74, 0x16, 0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00,
                                   0x14, 0x03, 0x00, 0x0a, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20}},

                {.size=64, .msg = {0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20, 0x52, 0x14, 0x65, 0x63, 0x74, 0x16,
                                   0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03,
                                   0x00, 0x0c, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65,
                                   0x63, 0x17, 0x74, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00,
                                   0x14, 0x03, 0x00, 0x0c, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20}},

                {.size=64, .msg = {0x14, 0x52, 0x65, 0x63, 0x17, 0x74, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14,
                                   0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0,
                                   0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x17, 0x00, 0x00,
                                   0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c,
                                   0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65, 0x63}},

                {.size=64, .msg = {0x17, 0x74, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14,
                                   0x03, 0x00, 0x0c, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52,
                                   0x65, 0x63, 0x17, 0x74, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00,
                                   0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00,
                                   0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14,
                                   0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0,
                                   0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x17, 0x00, 0x00,
                                   0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a,
                                   0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x53, 0x69, 0x6e}},

                {.size=64, .msg = {0x14, 0x67, 0x20, 0x52, 0x14, 0x65, 0x63, 0x74, 0x16, 0x00, 0xf7, 0x00, 0x14,
                                   0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x14, 0x00,
                                   0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20,
                                   0x52, 0x14, 0x65, 0x63, 0x74, 0x16, 0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20,
                                   0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x17, 0x00, 0x00, 0xf7}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x17,
                                   0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03,
                                   0x00, 0x0c, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65,
                                   0x63, 0x17, 0x74, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00,
                                   0x14, 0x03, 0x00, 0x0c, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20}},

                {.size=8, .msg = {0x14, 0x52, 0x65, 0x63, 0x17, 0x74, 0x00, 0xf7}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14,
                                   0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00,
                                   0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00,
                                   0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20}},

                {.size=16, .msg = {0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15,
                                   0xf7, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14,
                                   0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00,
                                   0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a,
                                   0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0x03, 0x00, 0x0a, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14,
                                   0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42,
                                   0x6f, 0x20, 0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20, 0x52, 0x14, 0x65, 0x63,
                                   0x74, 0x16, 0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00,
                                   0x14, 0x03, 0x00, 0x0a, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20}},

                {.size=64, .msg = {0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20, 0x52, 0x14, 0x65, 0x63, 0x74, 0x16,
                                   0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03,
                                   0x00, 0x0c, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00,
                                   0x00, 0x14, 0x03, 0x00, 0x0c, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20,
                                   0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x14, 0x00, 0x4d, 0x65}},

                {.size=64, .msg = {0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65, 0x63, 0x17, 0x74, 0x00, 0xf7, 0x14,
                                   0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x14, 0x00,
                                   0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65, 0x63, 0x17, 0x74, 0x00,
                                   0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00,
                                   0x14, 0x00, 0x32, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20}},

                {.size=64, .msg = {0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x14, 0x00, 0x32, 0x00, 0x15,
                                   0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03,
                                   0x00, 0x0a, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00,
                                   0x00, 0x14, 0x03, 0x00, 0x0a, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20,
                                   0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x14, 0x00, 0x4d, 0x65}},

                {.size=64, .msg = {0x14, 0x42, 0x6f, 0x20, 0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20, 0x52, 0x14,
                                   0x65, 0x63, 0x74, 0x16, 0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33,
                                   0x00, 0x00, 0x14, 0x03, 0x00, 0x0a, 0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f,
                                   0x20, 0x14, 0x53, 0x69, 0x6e, 0x14, 0x67, 0x20, 0x52, 0x14, 0x65, 0x63, 0x74,
                                   0x16, 0x00, 0xf7, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00}},

                {.size=64, .msg = {0x14, 0x03, 0x00, 0x0c, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0, 0x00, 0x20, 0x14,
                                   0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x17, 0x00, 0x00, 0xf7, 0x14, 0xf0,
                                   0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c, 0x14, 0x00, 0x4d,
                                   0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65, 0x63, 0x17, 0x74, 0x00, 0xf7,
                                   0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x03, 0x00, 0x0c}},

                {.size=16, .msg = {0x14, 0x00, 0x4d, 0x65, 0x14, 0x42, 0x6f, 0x20, 0x14, 0x52, 0x65, 0x63, 0x17,
                                   0x74, 0x00, 0xf7}},

                {.size=64, .msg = {0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x00, 0x14, 0x06, 0x00, 0x00, 0x14,
                                   0x00, 0x06, 0x13, 0x14, 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01, 0x15, 0xf7,
                                   0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x02, 0x00, 0x14, 0x06, 0x00,
                                   0x00, 0x14, 0x00, 0x06, 0x13, 0x14, 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01,
                                   0x15, 0xf7, 0x00, 0x00, 0x14, 0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00}},

                {.size=32, .msg = {0x14, 0x01, 0x00, 0x0c, 0x14, 0x02, 0x00, 0x00, 0x15, 0xf7, 0x00, 0x00, 0x14,
                                   0xf0, 0x00, 0x20, 0x14, 0x33, 0x00, 0x00, 0x14, 0x01, 0x00, 0x0c, 0x14, 0x02,
                                   0x00, 0x00, 0x15, 0xf7, 0x00, 0x00}}
        },
        {
                {.size=11, .msg = {0x16, 0xe7, 0x91, 0x30, 0x63, 0xe2, 0x07, 0x38, 0xad, 0x2c, 0xd6}},
                {.size=3, .msg = {0xac, 0x25, 0x36}},
                {.size=3, .msg = {0x01, 0x5c, 0xee}},
                {.size=12, .msg = {0xcd, 0xb7, 0x0a, 0x0d, 0x22, 0xe7, 0x31, 0xf5, 0xa5, 0x8d, 0xcb, 0xde}},
                {.size=3, .msg = {0x36, 0xff, 0x5c}},
                {.size=3, .msg = {0x30, 0x10, 0x90}},
                {.size=3, .msg = {0x68, 0xff, 0xfd}},
                {.size=3, .msg = {0x35, 0x17, 0x41}},
                {.size=3, .msg = {0xce, 0x39, 0x52}},
                {.size=3, .msg = {0x72, 0x4f, 0x4c}},
                {.size=3, .msg = {0x4d, 0xbf, 0xd8}},
                {.size=12, .msg = {0x2f, 0xc4, 0xb1, 0x93, 0xb2, 0x48, 0xef, 0x1d, 0x50, 0xbe, 0x4d, 0xe2}}
        }
};