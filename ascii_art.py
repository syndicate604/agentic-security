import random
import time

# Pre-made ASCII art patterns
PATTERNS = {
    "mountain": """
    /\\
   /  \\
  /    \\
 /      \\
/________\\
""",
    "heart": """
 /\\  /\\
 \\/\\/\\/
  \\  /
   \\/
""",
    "castle": """
    /\\
   /  \\
  /----\\
 /|  |  \\
 ||  |  ||
=||==|==||=
""",
    "star": """
    *
   /|\\
  /*|*\\
 /*/*\\*\\
/*/*/*\\*\\
""",
}

def show_pattern(name):
    """Display a pre-made ASCII art pattern"""
    if name in PATTERNS:
        print(PATTERNS[name])
    else:
        print("Available patterns:", ", ".join(PATTERNS.keys()))

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
    print("ASCII Art Gallery!")
    print("\nPre-made patterns:")
    for pattern_name in PATTERNS:
        print(f"\n{pattern_name.upper()}:")
        show_pattern(pattern_name)
    
    print("\nRandom Art Show:")
    animate_art(frames=5)
