import struct
import hashlib

class SHA1Hash:
    
    def __init__(self) -> None:
        pass

    def rotate(self, a, b):
        """
        The function `rotate(a, b)` performs a bitwise rotation operation on the input `a` by `b` bits in a
        32-bit system.
        
        :param a: The parameter `a` is the value that you want to rotate bitwise
        :param b: The parameter `b` in the `rotate` function represents the number of bits by which the
        integer `a` will be rotated to the left
        :return: The function `rotate(a, b)` takes two parameters `a` and `b`, and performs a bitwise
        rotation operation on `a` by `b` bits. The result is then bitwise ANDed with `0xFFFFFFFF` to ensure
        that the result is within the range of a 32-bit unsigned integer.
        """
        return ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF

    def padding(self, data):
        """
        The function `padding` adds padding to input data to ensure its length is a multiple of 64 bytes.
        
        :param data: The `padding` function you provided is used to add padding to a given `data` input
        according to the MD5 padding scheme. The `data` parameter is the input data that needs to be padded
        before processing it with the MD5 algorithm
        :return: The `padding` function takes a `data` input, adds padding to it, and returns the padded
        data.
        """
        padding = b"\x80" + b"\x00" * (63 - (len(data) + 8) % 64)
        padded_data = data + padding + struct.pack(">Q", 8 * len(data))
        return padded_data

    def split_blocks(self, data):
        """
        The function `split_blocks` takes a string `data` and splits it into blocks of length 64.
        
        :param data: The `split_blocks` function takes a `data` input, which is a sequence of characters or
        bytes that you want to split into blocks of length 64. The function will return a list of blocks
        where each block contains up to 64 characters or bytes from the input `data`
        :return: The `split_blocks` function takes a string `data` as input and returns a list of substrings
        where each substring has a length of 64 characters.
        """
        return [
            data[i : i + 64] for i in range(0, len(data), 64)
        ]
        
    def expand_block(self,block):
        """
        The function `expand_block` takes a block of data, expands it using a specific algorithm, and
        returns the expanded block.
        
        :param block: The `expand_block` function takes a block of data as input and expands it using the
        SHA-1 expansion algorithm. The input block is expected to be a list of 16 integers
        :return: The function `expand_block` takes a block of data as input and expands it using a specific
        algorithm. It returns a list of 80 elements where each element is the result of applying the
        algorithm to the corresponding element in the input block.
        """
        w = list(struct.unpack(">16L", block)) + [0] * 64
        
        for i in range(16, 80):
            a = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w[i] = self.rotate((a), 1)
        
        return w

    def Hash(self, data):
        """
        The function `Hash` calculates a hash value using the SHA-1 algorithm on the input data.
        
        :param data: It looks like the code you provided is a Python function for hashing data using the
        SHA-1 algorithm. The function takes input data, pads it, splits it into blocks, and then performs
        the SHA-1 hashing algorithm on each block
        :return: The function `Hash(data)` is returning a hexadecimal string representing the final hash
        value after processing the input data through the SHA-1 hashing algorithm. The hash value is a
        concatenation of five 32-bit integers (h[0], h[1], h[2], h[3], h[4]) converted to hexadecimal
        format.
        """
        h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        
        padded_data = self.padding(data)
        blocks = self.split_blocks(padded_data)
        
        for block in blocks:
            expanded_block = self.expand_block(block)
            
            a, b, c, d, e = h
            for i in range(0, 80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                    
                a, b, c, d, e = (
                    (self.rotate(a, 5) + f + e + k + expanded_block[i]) & 0xFFFFFFFF,
                    a,
                    self.rotate(b, 30),
                    c,
                    d
                )
                
        h = (
            (h[0] + a) & 0xFFFFFFFF,
            (h[1] + b) & 0xFFFFFFFF,
            (h[2] + c) & 0xFFFFFFFF,
            (h[3] + d) & 0xFFFFFFFF,
            (h[4] + e) & 0xFFFFFFFF,
        )
        
        return "%08x%08x%08x%08x%08x" % tuple(h)
    
def main():
    sha = SHA1Hash()
    data = b"Hello, SHA-1!!"
    
    sha_result = sha.Hash(data)
    sha256 = hashlib.sha256(data)
    sha384 = hashlib.sha384(data)
    sha512 = hashlib.sha512(data)
    
    
    print(sha_result)
    print(sha256.hexdigest())
    print(sha384.hexdigest())
    print(sha512.hexdigest())
    
if __name__ == "__main__":
    main()