# PSP (Password Share Protocol)

# Requests
## Structure
The first 4 bytes are reserved for the Length of the message in big endian.
This includes the HTTP method name and a potential body afterwards.

## Example
## `[00 00 00 10][47 45 54][20][48 45 4C 4C 4F 20 57 4F 52 4C 44 21]`

1. **Section "Length Field": `[00 00 00 10]`**:
    - The 4 byte big-endian unsigned encoded length
    - This is the length of every byte *after* the length field
    - In this example, this comes down to $10_{16}$ = $16_{10}$
    - The length of the whole message (including length field) hence is defined as 16 + 4 = 20

2. **Section "HTTP method": `[47 45 54]`**:
    - n (1 min.) bytes (utf-8), being the http method such as `GET`, `POST` or `DELETE`, this is case-insensitive: `DelETe` would also be fine
    - *Could* in theory be empty
    - must not contain the space character $20_{16}$ ($32_{10}$), see Section 3
    - In this example, the sequence comes down to `GET`

3. **Section "Separation": `[20]`**:
    - Separation section
    - must be the space character $20_{16}$ ($32_{10}$)
    - marks a separation between section 2 and 4
    - must be present, even if the body is empty

4. **Section "Body": `[48 45 4C 4C 4F 20 57 4F 52 4C 44 21]`**:
    - Body section in utf-8
    - Length is defined by the length field $-$ length of section 2 and 3
    - In this example, the length field was 16, 3 bytes were read for section 2 and 1 byte for section 3, the total length of the body hence is defined as 12 bytes
    - In this example, the bytes encode the string `HELLO WORLD!`

## Limitations
Since only 4 bytes are reserved for the Length of the Sections 2-4, the total maximum size for the body is $2^{32} - 1 = 4294967295 \approx 4.29$ GB. This assumes an empty http method.

# Responses
## Structure
The first 4 bytes are reserved for the Length of the message in big endian.
This includes the status and a potential body afterwards.

## Example
## `[00 00 00 1B][00 C8][20][4F 4B][0A][41 77 65 73 6F 6D 65 20 52 65 73 70 6F 6E 73 65 21]`

1. **Section "Length Field": `[00 00 00 1B]`**:
    - The 4 byte big-endian unsigned encoded length
    - This is the length of every byte *after* the length field
    - In this example, this comes down to $17_{16}$ = $23_{10}$
    - The length of the whole message (including length field) hence is defined as 23 + 4 = 27

2. **Section "Status Code": `[00 C8]`**:
    - The next two bytes are reserved as a http response code
    - Even though there are $(2^8)^2 = 65536$ possible codes, it is assumed to only be [valid codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
    - In this example, this comes down to the status code 200

3. **Section "Separation": `[20]`**:
    - Separation section
    - must be the space character $20_{16}$ ($32_{10}$)
    - marks a separation between section 2 and 4

4. **Section "Status Text": `[4F 4B]`**:
    - UTF-8 encoded text representing the http status text
    - Each code has its own text, but the text is read through this status text
    - Hence, there could be a status text sent that does not match the code. This is no error.
    - In this case, the sequence encodes for `OK`

5. **Section "Separation": `[0A]`**:
    - Separation section
    - must be the newline character $0A_{16}$ ($10_{10}$) 
    - marks a separation between section 4 and 6
    - must be present, even if the body is empty

6. **Section "Body": `[41 77 65 73 6F 6D 65 20 52 65 73 70 6F 6E 73 65 21]`**:
    - Body section in utf-8
    - Length is defined by the length field $-$ length of section 2, 3, 4 and 5
    - In this example, the length field was 16, 3 bytes were read for section 2 and 1 byte for section 3, the total length of the body hence is defined as 12 bytes
    - In this example, the bytes encode the string `Awesome Response!`
