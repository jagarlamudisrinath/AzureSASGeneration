import gnupg
from datetime import date
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
gpg = gnupg.GPG()

#get input data for servicer
servicer_name=str(input("Enter Servicer name: "))
servicer_email=str(input("Enter Servicer Email ID: "))
passphrase=str(input("Enter passphrase: "))
comment="GPG Key for {} generated on {} ".format(servicer_name,date.today())

# generate new GPG key pair with passphrase protection
input_data = gpg.gen_key_input(key_type='RSA', key_length=4096, passphrase=passphrase, name_real=servicer_name, name_email=servicer_email, name_comment=comment)
key = gpg.gen_key(input_data)

# export public key and save it in Azure Key Vault
public_key = gpg.export_keys(key.fingerprint)
credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://azuresftp.vault.azure.net/", credential=credential)
client.set_secret("public-key", public_key)

# export private key with passphrase protection and save it in Azure Key Vault
private_key = gpg.export_keys(key.fingerprint, True, passphrase=passphrase)
client.set_secret("private-key", private_key)
client.set_secret("passphrase", passphrase)