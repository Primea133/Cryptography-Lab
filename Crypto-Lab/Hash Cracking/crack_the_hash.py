import hashlib
import random
import string

def generate_random_string(length):
    """Generate a random string of specified length."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def first_preimage_attack(target_hash):
    """Perform a first pre-image attack using brute force."""
    while True:
        # Generate a random input
        random_input = generate_random_string(16)  # You can adjust the length as needed
        
        # Hash the input using SHA-256
        hashed_input = hashlib.sha256(random_input.encode()).hexdigest()
        
        # Check if the hash matches the target hash
        if hashed_input == target_hash:
            return random_input  # Return the pre-image if found

# Example usage:
target_hash = "5e99c40bdcf4803759655fb07dcf93b2752648a5cbdf1b2e2fd96f4618f12d4b"
pre_image = first_preimage_attack(target_hash)
print("Pre-image found:", pre_image)
