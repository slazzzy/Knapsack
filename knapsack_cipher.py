import gmpy2
import secrets
import json
import math

class KnapsackPublicKey:
    """Класс для представления открытого ключа."""
    def __init__(self, b_vector, p_mod):
        self.B = b_vector
        self.p = p_mod
        self.n = len(b_vector)

    def save(self, filename="public.key"):
        """Сохраняет открытый ключ в файл."""
        data = {
            'B': [str(x) for x in self.B],
            'p': str(self.p)
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Открытый ключ сохранен в файл: {filename}")

    @staticmethod
    def load(filename="public.key"):
        """Загружает открытый ключ из файла."""
        with open(filename, 'r') as f:
            data = json.load(f)
        b_vector = [gmpy2.mpz(x) for x in data['B']]
        p_mod = gmpy2.mpz(data['p'])
        return KnapsackPublicKey(b_vector, p_mod)

class KnapsackPrivateKey:
    """Класс для представления закрытого ключа."""
    def __init__(self, a_vector, r_exp):
        self.A = a_vector
        self.r = r_exp

    def save(self, filename="private.key"):
        """Сохраняет закрытый ключ в файл."""
        data = {
            'A': [str(x) for x in self.A],
            'r': str(self.r)
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Закрытый ключ сохранен в файл: {filename}")

    @staticmethod
    def load(filename="private.key"):
        """Загружает закрытый ключ из файла."""
        with open(filename, 'r') as f:
            data = json.load(f)
        a_vector = [gmpy2.mpz(x) for x in data['A']]
        r_exp = gmpy2.mpz(data['r'])
        return KnapsackPrivateKey(a_vector, r_exp)


class KnapsackCipher:
    """
    Реализует 0-2 мультипликативную рюкзачную криптосистему с поддержкой блочного шифрования.
    """
    def _text_to_chunks(self, text: str, n: int):
        """Разбивает текст на блоки и кодирует каждый в троичный вектор."""
        max_bits_per_chunk = math.floor(n * math.log2(3)) - 1
        chunk_size_bytes = max_bits_per_chunk // 8
        
        if chunk_size_bytes == 0:
            raise ValueError("Размер рюкзака n слишком мал для кодирования хотя бы одного байта.")

        message_bytes = text.encode('utf-8')
        chunks = []
        for i in range(0, len(message_bytes), chunk_size_bytes):
            chunk = message_bytes[i:i+chunk_size_bytes]
            num_representation = int.from_bytes(chunk, 'big')
            
            ternary_str = ""
            if num_representation == 0:
                ternary_str = "0"
            else:
                while num_representation > 0:
                    ternary_str = str(num_representation % 3) + ternary_str
                    num_representation //= 3
            
            padded_ternary = ternary_str.zfill(n)
            chunks.append([int(d) for d in padded_ternary])
        return chunks

    def _chunks_to_text(self, vectors: list):
        """Декодирует список троичных векторов в единый текст."""
        full_bytes = b''
        for vector in vectors:
            ternary_str = "".join(map(str, vector))
            num_representation = int(ternary_str, 3)
            byte_length = (num_representation.bit_length() + 7) // 8
            if byte_length > 0:
                full_bytes += num_representation.to_bytes(byte_length, 'big')
        
        try:
            return full_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return "Ошибка декодирования (возможно, неверный ключ или поврежденные данные)"

    @staticmethod
    def generate_keys(n=60, min_bits=32):
        print(f"Генерация ключей для рюкзака размером n={n}...")
        A = []
        current_prime = gmpy2.next_prime(secrets.randbits(min_bits))
        for _ in range(n):
            A.append(current_prime)
            current_prime = gmpy2.next_prime(current_prime)
        
        max_prod = gmpy2.mpz(1)
        for val in A:
            max_prod *= (val**2)
        
        p = gmpy2.next_prime(max_prod)
        p_minus_1 = p - 1
        
        while True:
            r = secrets.randbelow(int(p_minus_1 - 2)) + 2
            if gmpy2.gcd(r, p_minus_1) == 1:
                break
        
        B = [gmpy2.powmod(a, r, p) for a in A]
        
        public_key = KnapsackPublicKey(B, p)
        private_key = KnapsackPrivateKey(A, r)
        
        print("Генерация ключей успешно завершена.")
        return public_key, private_key

    def encrypt(self, message: str, public_key: KnapsackPublicKey) -> list[int]:
        """Шифрует сообщение, разбивая на блоки. Возвращает список шифртекстов."""
        chunks = self._text_to_chunks(message, public_key.n)
        encrypted_chunks = []
        
        for x_vector in chunks:
            C = gmpy2.mpz(1)
            for i in range(public_key.n):
                term = gmpy2.powmod(public_key.B[i], x_vector[i], public_key.p)
                C = gmpy2.mul(C, term) % public_key.p
            encrypted_chunks.append(int(C))
            
        return encrypted_chunks

    def decrypt(self, ciphertexts: list[int], private_key: KnapsackPrivateKey, public_key: KnapsackPublicKey) -> str:
        """Расшифровывает список шифртекстов."""
        p = public_key.p
        p_minus_1 = p - 1
        d = gmpy2.invert(private_key.r, p_minus_1)
        
        decrypted_vectors = []
        for C in ciphertexts:
            P_prime = gmpy2.powmod(C, d, p)
            
            x = [0] * len(private_key.A)
            temp_P = P_prime
            
            for i in range(len(private_key.A) - 1, -1, -1):
                a_i = private_key.A[i]
                if temp_P % (a_i**2) == 0:
                    x[i] = 2
                    temp_P //= (a_i**2)
                elif temp_P % a_i == 0:
                    x[i] = 1
                    temp_P //= a_i
            
            if temp_P != 1:
                raise RuntimeError("Ошибка расшифрования блока: не удалось полностью разложить P'.")
            
            decrypted_vectors.append(x)
            
        return self._chunks_to_text(decrypted_vectors)