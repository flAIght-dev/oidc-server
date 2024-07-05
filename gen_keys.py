from jwcrypto import jwk
import json

# Generare una nuova chiave RSA
key = jwk.JWK.generate(kty='RSA', size=2048)

# Salvare la chiave privata in un file
with open('private_key.pem', 'w') as f:
    f.write(key.export_to_pem(private_key=True, password=None).decode('utf-8'))

# Salvare la chiave pubblica in un file
with open('public_key.pem', 'w') as f:
    f.write(key.export_to_pem(private_key=False).decode('utf-8'))

# Creare il JWKS
jwks = jwk.JWKSet()
jwks.add(key)

# Salvare il JWKS in un file
with open('jwks.json', 'w') as f:
    f.write(jwks.export(private_keys=False))

print("JWKS generated and saved to 'jwks.json'")


