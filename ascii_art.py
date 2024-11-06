import random
import time

def generate_random_art(width=40, height=15):
    """Generate random ASCII art using #/@ characters"""
    characters = '#/@*+='
    art = []
    
    for _ in range(height):
        line = ''.join(random.choice(characters) for _ in range(width))
        art.append(line)
    
    return '\n'.join(art)

def animate_art(frames=10, delay=0.2):
    """Create animated ASCII art"""
    try:
        while frames > 0:
            print('\033[2J\033[H')  # Clear screen
            print(generate_random_art())
            time.sleep(delay)
            frames -= 1
    except KeyboardInterrupt:
        print("\nArt show stopped!")

if __name__ == "__main__":
    print("ASCII Art Show!")
    animate_art()
