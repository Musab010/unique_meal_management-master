from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Maak een RSA sleutel paar
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Exporteer de private key
private_key = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Exporteer de public key
public_key = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Sla de sleutels op in de data directory
with open("data/private_key.pem", "wb") as private_file:
    private_file.write(private_key)

with open("data/public_key.pem", "wb") as public_file:
    public_file.write(public_key)

print("Publieke en private sleutels zijn gegenereerd en opgeslagen in de data directory.")
