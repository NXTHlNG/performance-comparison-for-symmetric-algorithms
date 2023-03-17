import time
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, DES, DES3, ARC2, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pprint import pprint

# Set the message to encrypt and decrypt
message = b"This is a sample message to encrypt and decrypt"

with open("data/message.txt", "rb") as f:
    message = f.read()

key_16 = get_random_bytes(16)
key_8 = get_random_bytes(8)

# Set the encryption and decryption modes
# exluded "CTR", "EAX", "OpenPGP"
modes = ["CBC", "CFB", "ECB", "OFB"]

# Set the encryption algorithms to test
algorithms = [("AES", AES), ("DES", DES), ("DES3", DES3), ("ARC2", ARC2), ("Blowfish", Blowfish)]

# Set the number of iterations to perform for each test
num_iterations = 1

# Set up a dictionary to hold the results
results = {}

# Perform the tests for each algorithm and mode
for algorithm_name, algorithm in algorithms:
    for mode in modes:
        if (algorithm_name == "DES"):
            key = key_8
        elif (algorithm_name == "DES3"):
            key = DES3.adjust_key_parity(key_16)
        else:
            key = key_16

        # Create a new cipher object
        cipher = algorithm.new(key, getattr(algorithm, "MODE_" + mode.upper()))

        if (mode in ("CTR", "EAX", "OpenPGP")):
            padded_message = message
        else:
            padded_message = pad(message, getattr(algorithm, "block_size"))

        # Measure the time taken to encrypt the message
        start_time = time.time()
        encrypted_message = cipher.encrypt(padded_message)
        encryption_time = (time.time() - start_time) * 1000

        if hasattr(cipher, 'iv'):
            cipher = algorithm.new(key, getattr(algorithm, "MODE_" + mode.upper()), iv=cipher.iv)
        else:
            cipher = algorithm.new(key, getattr(algorithm, "MODE_" + mode.upper()))

        # Measure the time taken to decrypt the message
        start_time = time.time()
        padded_decrypted_message = cipher.decrypt(encrypted_message)
        decryption_time = (time.time() - start_time) * 1000

        if (mode in ("CTR", "EAX")):
            decrypted_message = padded_decrypted_message
        else:
            decrypted_message = unpad(padded_decrypted_message, getattr(algorithm, "block_size"))

        assert message == decrypted_message

        # Add the results to the dictionary
        results[(algorithm_name, mode)] = (encryption_time, decryption_time)

pprint(results)

# Create figure and axes objects
figure, axes = plt.subplots(figsize=(12, 8))

# Get cipher modes and times from results dictionary
cipher_modes = [f"{k[0]}-{k[1]}" for k in results.keys()]
encryption_times = [v[0] for v in results.values()]
decryption_times = [v[1] for v in results.values()]

# Set bar height and opacity
bar_height = 0.35
opacity = 0.8

# Create horizontal bar chart for encryption times
rects1 = axes.barh(cipher_modes, encryption_times, bar_height,
                   alpha=opacity, color='b', label='Encryption Time')
axes.bar_label(rects1)

# Create horizontal bar chart for decryption times
rects2 = axes.barh([x + bar_height for x in range(len(cipher_modes))], decryption_times, bar_height,
                   alpha=opacity, color='g', label='Decryption Time')
axes.bar_label(rects2)

# Set axis labels and title
axes.set_ylabel('Cipher-Mode')
axes.set_xlabel('Time (ms)')
axes.set_title('Performance of symmetric algorithms')

# Set y-tick labels and positions
axes.set_yticks([i + bar_height / 2 for i in range(len(cipher_modes))])
axes.set_yticklabels(cipher_modes)

# Add legend
axes.legend()

# Adjust layout and display plot
plt.tight_layout()
plt.show()
