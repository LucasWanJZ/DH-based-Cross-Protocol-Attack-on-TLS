from cypari2 import Pari

def generate_prime_product(hex_length,p):
    """Generates a product of prime numbers with a given hexadecimal length.

    Args:
        hex_length: The desired hexadecimal length of the product.

    Returns:
        A tuple containing the prime numbers used and their product.
    """
    pari = Pari()
    primes = [p]
    product = pari(p)
    
    # Start with a large prime and decrement until the product is large enough
    while True:
        p = pari.nextprime(p+1)

        product *= p
        primes.append(p)

        hex_string = hex(product)[2:]
        if len(hex_string) >= hex_length and len(hex_string) % 2 == 0:
            return primes, product

def print_hex(hex_string):
    """Prints a hexadecimal string in 16-byte blocks."""
    for i in range(0, len(hex_string), 32):
        print(hex_string[i:i+32])

def filter_product(p):
    primes, product = generate_prime_product(600, p)
    hex_product = hex(product)[2:]
    print("Primes:", primes)
    print("Product:")
    print_hex(hex_product)
    print("Product length:", len(hex_product))

    try :
        hex_len = hex(round(len(hex_product)/2))
        p_len = int(hex_len[3:],16)
        
        print("Prime P :")
        print_hex(hex_product[0:p_len*2])
    
        a_len = int(hex_product[p_len*2:p_len*2+2],16)
        print("Length of A :", a_len)

        print("A :")
        print_hex(hex_product[p_len*2+2:p_len*2+2+a_len*2])

        prefix = p_len*2+2+a_len*2
        b_len = int(hex_product[prefix:prefix+2],16)
        print("Length of B :", b_len)

        print("B :")
        print_hex(hex_product[prefix+2:prefix+2+b_len*2])

        prefix = prefix+2+b_len*2   
        base_len = int(hex_product[prefix:prefix+2],16)
        print("Length of Base :", base_len)

        print("Base :")
        print_hex(hex_product[prefix+2:prefix+2+base_len*2])

        prefix = prefix+2+base_len*2
        order_len = int(hex_product[prefix:prefix+2],16)
        print("Length of Order :", order_len)

        print("order :")
        print_hex(hex_product[prefix+2:prefix+2+order_len*2])

        prefix = prefix+2+order_len*2
        cofactor_len = int(hex_product[prefix:prefix+2],16)
        print("Length of cofactor :", cofactor_len)

        print("Cofactor :")
        print_hex(hex_product[prefix+2:prefix+2+cofactor_len*2])

        prefix = prefix+2+cofactor_len*2
        plb = int(hex_product[prefix:prefix+2],16)
        print("public len byte :", plb)

        print("Lower bound :",(262-2*p_len))
        C = a_len+b_len+base_len+order_len+cofactor_len+7
        print("C :",C)
        print("Length of g :", (2*p_len-261+C))

        prefix = prefix+2
        print("Length of remaining :", len(hex_product[prefix:]))
        print("Remaining :")
        print_hex(hex_product[prefix:])

    except Exception as e:
        plb = 0
        print("Error : ",e)
    
    return plb, primes

plb, primes = filter_product(517948811)
while plb != 97:
    plb, primes = filter_product(primes[1])