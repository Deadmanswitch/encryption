// -----------------------------------------------------------------------------
//  Copyright (c) 2025 Deadmanswitch.com, Inc.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// -----------------------------------------------------------------------------

let browserCrypto: Crypto;

export const browserInit = (crypto: any) => {
  browserCrypto = crypto;
}

/**
 * Generates base64 encoded encryption key from provided password and initialization vector (IV).
 */
export const browserGenerateKey = async (password: string, ivv: string): Promise<string> => {
  if (!browserCrypto.subtle?.importKey) {
    throw new Error('browserCrypto.subtle.importKey is not supported');
  }

  const encoder = new TextEncoder();
  const iterations = 100000;
  const bytesize = 32;

  const importedKey = await browserCrypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  const derivedBits = await browserCrypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: Buffer.from(ivv, 'base64'),
      iterations,
      hash: 'SHA-256',
    },
    importedKey,
    bytesize * 8,
  );

  return Buffer.from(derivedBits).toString('base64');
};

/**
 * Generates base64 encoded encryption hash from provided key and initialization vector (IV).
 * Output hash could be safely stored and used as a fingerprint without exposing original password.
 */
export const browserGenerateHash = async (password: string, ivv: string): Promise<string> => {
  const key = await browserGenerateKey(password, ivv);
  return await browserGenerateKey(key, ivv);
}

/**
 * Asynchronously decrypts text using the provided key and initialization vector (IV),
 * and invokes the specified event handler with the decrypted result.
 */
export const browserDecryptText = async (key: string, ivv: string, text: string, event: (cipher: string) => void): Promise<void> => {
  if (!browserCrypto.subtle?.importKey) {
    throw new Error('browserCrypto.subtle.importKey is not supported');
  }

  const importedKey = await browserCrypto.subtle.importKey(
    'raw',
    Buffer.from(key, 'base64'),
    { name: 'AES-CBC' },
    false,
    ['decrypt']
  );

  const decryptedText = await browserCrypto.subtle.decrypt(
    { name: 'AES-CBC', iv: Buffer.from(ivv, 'base64'), },
    importedKey,
    Buffer.from(text, 'base64')
  );

  event(new TextDecoder().decode(decryptedText));

  return Promise.resolve();
}
