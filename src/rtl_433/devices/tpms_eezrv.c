/** @file
    EezTire E618 TPMS and Carchet TPMS (same protocol).

    Copyright (C) 2023 Bruno OCTAU (ProfBoc75), Gliebig, and Karen Suhm
    Modified 2026 for improved robust decoding (Manus AI)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "decoder.h"

/**
EezTire E618 TPMS and Carchet TPMS (same protocol).

- Eez RV supported TPMS sensor model E618 : https://eezrvproducts.com/shop/ols/products/tpms-system-e518-anti-theft-replacement-sensor-1-ea
- Carchet TPMS: http://carchet.easyofficial.com/carchet-rv-trailer-car-solar-tpms-tire-pressure-monitoring-system-6-sensor-lcd-display-p6.html
- TST (Truck Systems Technologies) 507 Series TPMS : https://github.com/cterwilliger/tst_tpms

The device uses OOK (ASK) encoding.
The device sends a transmission every 1 second when quick deflation is detected, every 13 - 23 sec when quick inflation is detected, and every 4 min 40 s under steady state pressure.
A transmission starts with a preamble of 0x0000 and the packet is sent twice.

S.a issue #2384, #2657, #2063, #2677, #2819

Data collection parameters on URH software were as follows:
    Sensor frequency: 433.92 MHz
    Sample rate: 2.0 MSps
    Bandwidth: 2.0 Hz
    Gain: 125

    Modulation is ASK (OOK). Packets in URH arrive in the following format:

    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa [Pause: 897679 samples]
    aaaaaaaa5956a5a5a6555aaa65959999a5aaaaaa [Pause: 6030 samples]
    aaaaaaaa5956a5a5a6555aaa65959999a5aaaaaa [Pause: 11176528 samples]

    Decoding is Manchester I.  After decoding, the packets look like this:

    00000000000000000000000000000000000000
    0000de332fc0b7553000
    0000de332fc0b7553000

 Using rtl_433 software, packets were detected using the following command line entry:
 rtl_433 -X "n=Carchet,m=OOK_MC_ZEROBIT,s=50,l=50,r=1000,invert" -s 1M

 Data layout:

    PRE CC IIIIII PP TT FF FF

- PRE : FFFF
- C : 8 bit CheckSum, modulo 256 with overflow flag
- I: 24 bit little-endian ID
- P: 8 bit pressure  P * 2.5 = Pressure kPa
- T: 8 bit temperature   T - 50 = Temperature C
- F: 16 bit status flags: 0x8000 = low battery, 0x1000 = quick deflation, 0x3000 = quick inflation, 0x0000 = static/steady state

Raw Data example :

    ffff 8b 0d177e 8f 4a 10 00

Format string:

    CHECKSUM:8h ID:24h KPA:8d TEMP:8d FLAG:8b 8b

Decode example:

    CHECKSUM:8b ID:0d177e KPA:8f TEMP:4a FLAG:10 00

*/

static inline uint8_t bit_at_local(const uint8_t *bytes, unsigned bit)
{
    return (uint8_t)(bytes[bit >> 3] >> (7 - (bit & 7)) & 1);
}

static int validate_and_output(r_device *decoder, uint8_t *cc, uint8_t *b, int row)
{
    // Verify checksum
    int computed_checksum = add_bytes(b, 7);
    if (computed_checksum > 0xff) {
        computed_checksum |= 0x80;
    }

    if ((computed_checksum & 0xff) != cc[0]) {
        return 0; // Fail
    }
	
	// AJW 20260608 -- GHOST FILTER: Drop mathematically valid but completely empty RF noise packets
	/*
	From Gemini AI
	A normal TPMS packet burst is incredibly brief. At a standard sample rate, a signal length of 559,999 samples 
	is an absolute eternity—roughly a quarter of a second of continuous, unbroken radio energy.Because we just 
	discovered that your RF line logic is inverted (where a flat carrier-off state or a stuck-low state maps to a constant 
	logic state), the CC1101 receiver's data slicer got "stuck" processing a massive, uninterrupted wall of static or 
	unmodulated carrier wave.As the decoder shifted through that massive mountain of digital noise, the bit-slicer 
	eventually encountered a sequence of raw data that looked like 00 00 00 00 00 00 00 00. The code alignment found 
	its "preamble match," ran the addition math, hit the $0=0$ loophole, and published the phantom TPMS sensor.
	*/
	
    if (cc[0] == 0x00 && b[0] == 0x00 && b[3] == 0x00) {
        decoder_log(decoder, 2, __func__, "Dropped ghost packet (All-Zero RF Noise)");
        return DECODE_ABORT_EARLY; // Or return 0; depending on your exact function definitions
    }

    // Success! Process the data.
    int temperature_C      = b[4] - 50;
    int flags1             = b[5];
    int flags2             = b[6];
    int fast_leak_detected = (flags1 & 0x10);
    int infl_detected      = (flags1 & 0x20) >> 5;

    int fast_leak      = fast_leak_detected && !infl_detected;
    float pressure_kPa = (((flags2 & 0x01) << 8) + b[3]) * 2.5f;
    int low_batt = flags1 >> 7;

    char id_str[7];
    snprintf(id_str, sizeof(id_str), "%02x%02x%02x", b[0], b[1], b[2]);

    char flags_str[5];
    snprintf(flags_str, sizeof(flags_str), "%02x%02x", flags1, flags2);

    data_t *data = data_make(
            "model",            "",             DATA_STRING, "EezTire-E618",
            "type",             "",             DATA_STRING, "TPMS",
            "id",               "",             DATA_STRING, id_str,
            "battery_ok",       "Battery_OK",   DATA_INT,    !low_batt,
            "pressure_kPa",     "Pressure",     DATA_FORMAT, "%.0f kPa", DATA_DOUBLE, (double)pressure_kPa,
            "temperature_C",    "Temperature",  DATA_FORMAT, "%.1f C", DATA_DOUBLE, (double)temperature_C,
            "flags",            "Flags",        DATA_STRING, flags_str,
            "fast_leak",        "Fast Leak",    DATA_INT,    fast_leak,
            "inflate",          "Inflate",      DATA_INT,    infl_detected,
            "mic",              "Integrity",    DATA_STRING, "CHECKSUM",
            NULL);

    decoder_output_data(decoder, data);
    return 1;
}

static int tpms_eezrv_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    uint8_t const preamble_pattern[] = {0xff, 0xff};
    uint8_t const preamble_pattern_inv[] = {0x00, 0x00};

    for (int r = 0; r < bitbuffer->num_rows; r++) {
        
        // Try searching for both polarities
        int pos = bitbuffer_search(bitbuffer, r, 0, preamble_pattern, 12);
        int inverted_search = 0;

        if (pos >= bitbuffer->bits_per_row[r]) {
            pos = bitbuffer_search(bitbuffer, r, 0, preamble_pattern_inv, 12);
            inverted_search = 1;
        }

        if (pos < bitbuffer->bits_per_row[r]) {
            // Dynamic Start
            uint8_t target_bit = inverted_search ? 0 : 1;
            while (pos < bitbuffer->bits_per_row[r] && bit_at_local(bitbuffer->bb[r], pos) == target_bit) {
                pos++;
            }

            if (pos + 64 <= bitbuffer->bits_per_row[r]) {
                uint8_t b[7];
                uint8_t cc[1];

                bitbuffer_extract_bytes(bitbuffer, r, pos, cc, 8);
                bitbuffer_extract_bytes(bitbuffer, r, pos + 8, b, 56);

                if (inverted_search) {
                    cc[0] = ~cc[0];
                    for (int i = 0; i < 7; i++) b[i] = ~b[i];
                }

                // TRY 1: Current Polarity
                if (validate_and_output(decoder, cc, b, r)) return 1;

                // TRY 2: Flip Polarity (Fail-safe)
                cc[0] = ~cc[0];
                for (int i = 0; i < 7; i++) b[i] = ~b[i];
                if (validate_and_output(decoder, cc, b, r)) return 1;
            }
        }
    }

    return DECODE_ABORT_EARLY;
}

static char const *const output_fields[] = {
        "model",
        "type",
        "id",
        "battery_ok",
        "pressure_kPa",
        "temperature_C",
        "flags",
        "fast_leak",
        "inflate",
        "mic",
        NULL,
};

r_device const tpms_eezrv = {
        .name        = "EezTire E618, Carchet TPMS, TST-507 TPMS",
        .modulation  = OOK_PULSE_MANCHESTER_ZEROBIT,
        .short_width = 49,  // AJW
        .long_width  = 103,  // AJW
        .reset_limit = 135, // AJW 
        .decode_fn   = &tpms_eezrv_decode,
        .fields      = output_fields,
};
