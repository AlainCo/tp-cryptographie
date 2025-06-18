# TP de Cryptographie en Python

Ce dépôt contient deux programmes de test de cryptographie en Python. Ces programmes démontrent les principes de base du chiffrement symétrique et asymétrique.

## Table des matières

- [TP de Cryptographie en Python](#tp-de-cryptographie-en-python)
  - [Table des matières](#table-des-matières)
  - [tp-crypto-sym.py](#tp-crypto-sympy)
    - [Description](#description)
    - [Fonctionnalités](#fonctionnalités)
    - [Utilisation](#utilisation)
  - [tp-crypto-asym.py](#tp-crypto-asympy)
    - [Description](#description-1)
    - [Fonctionnalités](#fonctionnalités-1)
    - [Utilisation](#utilisation-1)

## tp-crypto-sym.py

### Description

Ce programme démonstre les principes de base du chiffrement symétrique en utilisant l'algorithme AES (Advanced Encryption Standard). Il permet de chiffrer et déchiffrer des fichiers en utilisant des clés symétriques.

### Fonctionnalités

- Calcul du hash SHA-256 d'un fichier.
- Chiffrement d'un fichier en utilisant AES-256 en mode ECB, CBC ou GCM.
- Déchiffrement d'un fichier chiffré.
- Vérification de l'intégrité des données en comparant les hashes avant et après le déchiffrement.

### Utilisation

1. Assurez-vous d'avoir installé la bibliothèque `cryptography` :
   ```bash
   pip install cryptography

2. Exécutez le programme :

   ```bash
    python tp-crypto-sym.py

## tp-crypto-asym.py

### Description

Ce programme démontre les principes de base du chiffrement asymétrique en utilisant l'algorithme RSA (Rivest-Shamir-Adleman). Il permet de générer des paires de clés RSA, de chiffrer et déchiffrer des fichiers, et de signer et vérifier des fichiers.

### Fonctionnalités

- Génération d'une paire de clés RSA (privée et publique).
- Chiffrement d'un fichier en utilisant une clé publique RSA et une clé symétrique AES.
- Déchiffrement d'un fichier chiffré en utilisant une clé privée RSA et une clé symétrique AES.
- Signature d'un fichier en utilisant une clé privée RSA.
- Vérification de la signature d'un fichier en utilisant une clé publique RSA.

### Utilisation

1. Assurez-vous d'avoir installé la bibliothèque cryptography :

    ```bash
    pip install cryptography

2. Exécutez le programme :

   ```bash
    python tp-crypto-asym.py

## Licence

Ce projet est sous licence APACHE.

## Auteur

Alain Co
