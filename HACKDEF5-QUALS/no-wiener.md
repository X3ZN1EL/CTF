# No-Wiener - HACKDEF5 QUALS

## Contexto

```
Logramos hacer 2 capturas de trafico en texto plano entre un usuario y una app maliciosa, la primera captura tenia solo el texto "0.265-0.267", en la segunda captura detectamos que tiene un certificado y un cifrado, sin embargo, no hemos podido romper la llave, tal vez con tus conocimiento en criptografia podamos decifrar el mensaje.
```

## Analisis 

Analizando el archivo captura2.pcapng con wireshark se hace descubrimiento del certificado (publica.pem)

![1](images/captura2-publica.png) 

Obteniendo lo anterior, es posible extraer los valores para n (modulo) y e (exponente publico)

```
-----BEGIN PUBLIC KEY-----
MIIBYDANBgkqhkiG9w0BAQEFAAOCAU0AMIIBSAKBoQCxX+37+WTP6Hu+AEgVk9l4
4pLpO+noc7DBp0Tz5JsnPVjrfjxJuS2cy5ETmkPWCjksW2k1A4mZ0uH35rmGRFrw
wF0KfRiq6mFIlsAC2AfiNlNwOTaKh25SmuTVDjaPLlhVgiWU32v4CLPAqqmCR1N5
RCo3uHyrZ6ruWrujL6AEoHZhQ6srv2UShQTToi9o8rKUT5jSnyRP0Lrxd4wKweiF
AoGhAIssihBwxmVOlUJ0m3AiN8vPAXbvjPEyxGrgUxQCowvcJtjegh16TqxJG7TR
Z7KUlMO2VgwGhpI/pTbqB0TbfzbQoJrEszIBm19l/q1JbV2mbtUFsutPfN2inDht
+IPLIdE3CBSvgb73XWPTM0LKONhqraYgQoNdLkXxGjMKmm+t6Lznj+ZDlwE8/Xva
ORmhG90EfnoAl4K6TAmDWqfGazk=
-----END PUBLIC KEY-----
```

Guardando el certificado en un archivo podemos interacturar con sus respectivos valores.

![2](images/captura2-analisis.png)

```
n = 14422688374274920572715395128926132280595287934645638027959795836205137543653980550156766522505145551128183562644774615059260775416926464729972596934129030609422031372050166979736413980630811109343334686473533072167129077450986448915506284017983212743800587370242324753323365471078620481393965890479782789461968308519897250944008928509347469992748228174562804102616346793136392788633733

e = 11316510661877813128203889307099294767461301841140854029486490638430945322415358761173905211885087878312984709212688026905076251153493333579921988798425820581906822056389451075929099988451241842915981402211758955779771230807005368547992624852051079152997394614596105469532784575056886989589972147986771158846508898650618412127467361549133671378974785643609622137218775248446077895338809
```

Al ser un reto con un exponente publico muy alto lo primero que se hizo a prueba fue un [Wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack). No obstante este ataque no fue posible debido a la condicion de la llave privada (d) ```d > 1/3N^1/4``` en la generación de parámetros impide el ataque. Descartando Wiener attack se utiliza el ataque [Boneh Durfee](https://eprint.iacr.org/2020/1214.pdf) para hacer una recuperacion de la llave privada, tomando en cuenta que en el contexto del reto se mencionan '0.265-0.267' como primer captura. Tomando mas sentido en esos valores decimales se refiere a el valor delta de la operacion.

El ataque funciona si el exponente privado d es demasiado pequeño en comparación con el módulo:

![3](images/boneh-at.png)

El ataque nos permite romper el RSA y el exponente privado (d). Utilizando la implementacion en [sage](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage)

```
d < N^delta
```

Reemplazando dentro del script de sage los siguientes valores.

```
delta = 0.267 # this means that d < N^delta
m = 5 # size of the lattice (bigger the better/slower)
```

Se obtiene la llave privada.

```
d = 218979779814309500204439653464303451799486637529239198517332627463475434001021587862090965739252
```
![4](images/sage-im.png)

Como ultimo paso solo es necesario extraer el archivo cifrado dentro del archivo pcap. Para esto como una buena practica siempre se debe extrar el valor original en su formato hexadecimal para conservar la integridad.

```
ciphertext = 9fffdfb228c0fd77f52c88fc1506368102243025aa2ca2eb6eac452444f1dd9207f3621c97bfc5592ce66ecfcb668b4cec49df9a1c1ce12a1bc6050749712742d3fe775c3bf346d1e7645faefad453f50119c698b49e11aa6ef8fad9818aeb9a29ae2b2643a2f7499548bbe387d0141511d2629cc11998e64baa6d8f055bc56d7b219029bec8165c6f53e99716c8402dbc52ed48a53ea47239d38c30a8cd96cc

```

![5](images/flag-enc.png)

## FLAG

```python
#!/usr/bin/env python3
# xeniel was here

from Crypto.Util.number import *
import binascii

d = 2189797798143095002044396534643034517994866375292391985173326274634754340010215878620909657392520077689
n = 14422688374274920572715395128926132280595287934645638027959795836205137543653980550156766522505145551128183562644774615059260775416926464729972596934129030609422031372050166979736413980630811109343334686473533072167129077450986448915506284017983212743800587370242324753323365471078620481393965890479782789461968308519897250944008928509347469992748228174562804102616346793136392788633733
c = '9fffdfb228c0fd77f52c88fc1506368102243025aa2ca2eb6eac452444f1dd9207f3621c97bfc5592ce66ecfcb668b4cec49df9a1c1ce12a1bc6050749712742d3fe775c3bf346d1e7645faefad453f50119c698b49e11aa6ef8fad9818aeb9a29ae2b2643a2f7499548bbe387d0141511d2629cc11998e64baa6d8f055bc56d7b219029bec8165c6f53e99716c8402dbc52ed48a53ea47239d38c30a8cd96cc'

msg = binascii.unhexlify(c)
c = bytes_to_long(msg)
print(long_to_bytes(pow(c,d,n)))

# Hackdef{B0n3hDurf33_3s_un_gr4n_4l14d0}
```

## SOLVER

```python

#!/usr/bin/env sage
# xeniel was here

from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import binascii
import time

############################################
# Config
##########################################

"""
Setting debug to true will display more informations
about the lattice, the bounds, the vectors...
"""
debug = True

"""
Setting strict to true will stop the algorithm (and
return (-1, -1)) if we don't have a correct 
upperbound on the determinant. Note that this 
doesn't necesseraly mean that no solutions 
will be found since the theoretical upperbound is
usualy far away from actual results. That is why
you should probably use `strict = False`
"""
strict = False

"""
This is experimental, but has provided remarkable results
so far. It tries to reduce the lattice as much as it can
while keeping its efficiency. I see no reason not to use
this option, but if things don't work, you should try
disabling it
"""
helpful_only = True
dimension_min = 7 # stop removing if lattice reaches that dimension

############################################
# Functions
##########################################

# display stats on helpful vectors
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1

    print(nothelpful, "/", BB.dimensions()[0], " vectors are not helpful")

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB

    # we start by checking from the end
    for ii in range(current, -1, -1):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            # let's check if it affects other vectors
            for jj in range(ii + 1, BB.dimensions()[0]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj

            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == 0:
                print("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-1)
                return BB

            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-1)
                    return BB
    # nothing happened
    return BB

""" 
Returns:
* 0,0   if it fails
* -1,-1 if `strict=true`, and determinant doesn't bound
* x0,y0 the solutions of `pol`
"""
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May
    
    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """

    # substitution (Herrman and May)
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u) # u = xy + 1
    polZ = Q(pol).lift()

    UU = XX*YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ(u, x, y)^kk
            gg.append(xshift)
    gg.sort()

    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
    
    # y-shifts (selected by Herrman and May)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y^jj * polZ(u, x, y)^kk * modulus^(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift) # substitution
    
    # y-shifts list of monomials
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u^kk * y^jj)

    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)

    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus^mm, nn-1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print("failure")
            return 0,0

    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus^mm)
    
    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus^(mm*nn)
    if det >= bound:
        print("We do not have det < bound. Solutions might not be found.")
        print("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")

    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus^mm)

    # LLL
    if debug:
        print("optimizing basis of the lattice via LLL, this can take a long time")

    BB = BB.LLL()

    if debug:
        print("LLL is done!")

    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print("looking for independent vectors in the lattice")
    found_polynomials = False
    
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)

            # resultant
            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)

            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        print("no independant vectors could be found. This should very rarely happen...")
        return 0, 0
    
    rr = rr(q, q)

    # solutions
    soly = rr.roots()

    if len(soly) == 0:
        print("Your prediction (delta) is too small")
        return 0, 0

    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]

    #
    return solx, soly

def example():
    ############################################
    # How To Use This Script
    ##########################################

    with open('publica.pem') as f:
        key = RSA.importKey(f.read())

    # the modulus
    N = key.n

    # the public exponent
    e = key.e

    print('n: ' + str(N)+'\n')
    print('e: ' + str(e)+'\n')
    #
    # The problem to solve (edit the following values)
    #  
    # the hypothesis on the private exponent (the theoretical maximum is 0.292)
    delta = 0.267 # this means that d < N^delta

    #
    # Lattice (tweak those values)
    #
    # you should tweak this (after a first run), (e.g. increment it until a solution is found)
    m = 5 # size of the lattice (bigger the better/slower)

    # you need to be a lattice master to tweak these
    t = int((1-2*delta) * m)  # optimization from Herrmann and May
    X = 2*floor(N^delta)  # this _might_ be too much
    Y = floor(N^(1/2))    # correct if p, q are ~ same size

    #
    # Don't touch anything below
    #

    # Problem put in equation
    P.<x,y> = PolynomialRing(ZZ)
    A = int((N+1)/2)
    pol = 1 + x * (A + y)

    #
    # Find the solutions!
    #

    # Checking bounds
    if debug:
        print("=== checking values ===")
        print("* delta:", delta)
        print("* delta < 0.292", delta < 0.292)
        print("* size of e:", int(log(e)/log(2)))
        print("* size of N:", int(log(N)/log(2)))
        print("* m:", m, ", t:", t)

    # boneh_durfee
    if debug:
        print("=== running algorithm ===")
        start_time = time.time()

    solx, soly = boneh_durfee(pol, e, m, t, X, Y)

    # found a solution?
    if solx > 0:
        print("=== solution found ===")
        if False:
            print("x:", solx)
            print("y:", soly)

        d = int(pol(solx, soly) / e)
        print("private key found:", d)
    else:
        print("=== no solution was found ===")

    if debug:
        print("=== %s seconds ===" % (time.time() - start_time))
    
    c = '9fffdfb228c0fd77f52c88fc1506368102243025aa2ca2eb6eac452444f1dd9207f3621c97bfc5592ce66ecfcb668b4cec49df9a1c1ce12a1bc6050749712742d3fe775c3bf346d1e7645faefad453f50119c698b49e11aa6ef8fad9818aeb9a29ae2b2643a2f7499548bbe387d0141511d2629cc11998e64baa6d8f055bc56d7b219029bec8165c6f53e99716c8402dbc52ed48a53ea47239d38c30a8cd96cc'
    msg = binascii.unhexlify(c)
    c = bytes_to_long(msg)
    print('\nFlag: ' + str(long_to_bytes(pow(c,d,N))))

if __name__ == "__main__":
    example()

```
