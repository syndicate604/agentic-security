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
    "dragon": """
      /\\    /\\
     /  \\__/  \\
    /          \\
   / ^      ^   \\
  /  @      @    \\
 /        <>      \\
/  |\\        /\\   \\
\\__| \\______/  \\__/
""",
    "crystal": """
   /\\/\\/\\
  /<>><>\\
 /\\/>></\\
/<>\\/<>/\\
\\/\\/\\/\\/
""",
    "vortex": """
/\\/\\/\\/\\/\\
\\/@@@@@@@/
/\\#####/\\
\\/@@@@@/
/\\###/\\
\\/@@@/
/\\#/\\
\\/@/
/\\
""",
    "maze": """
╔════╗╔═╗
║╔╗╔╗║║█║
╚╝║║╚╝║█║
╔╗║║╔╗║█║
║║║║║║║█║
║║║║║║║█║
╚╝╚╝╚╝╚═╝
""",
    "scroll": """
    .-------------------.
   /  Hello, traveler!   \\
  /                       \\
 /    Ancient wisdom       \\
|     lies within...       |
|                          |
|     ~ The Scribe ~      |
 \\                       /
  \\                     /
   \\                   /
    '-------------------'
""",
    "computer": """
  .----------------------------.
  |  .-----------------------. |
  |  |                       | |
  |  |    > CODE MASTER     | |
  |  |    > LOADING...      | |
  |  |    > READY           | |
  |  |                      | |
  |  |    Press any key     | |
  |  |                      | |
  |  '-----------------------' |
  |     .------------------.  |
  |    /|=================='  |
  |   / |__________________. |
  '---------------------------'
""",
    "billboard": """
  .======================================.
  |  .--------------------------------.  |
  |  |                                |  |
  |  |      WELCOME TO THE SHOW!      |  |
  |  |         ~~~~~~~~~~~~           |  |
  |  |     Today's Performance:       |  |
  |  |      ASCII Art Gallery         |  |
  |  |                                |  |
  |  '--------------------------------'  |
  |      ||                    ||       |
  |      ||                    ||       |
  '======================================'
""",
    "wow": """
W   W    W   W  OOOOO  W   W
W   W    W   W  O   O  W   W
W   W    W   W  O   O  W   W
W W W    W   W  O   O  W   W
WW WW    W W W  O   O  W   W
W   W     W W   O   O  W   W
W   W      W    OOOOO   WWW
""",
    "hello": """
H   H  EEEEE  L      L      OOOOO
H   H  E      L      L      O   O
H   H  E      L      L      O   O
HHHHH  EEEE   L      L      O   O
H   H  E      L      L      O   O
H   H  E      L      L      O   O
H   H  EEEEE  LLLLL  LLLLL  OOOOO
""",
    "mega": """
MM   MM  EEEEE   GGGGG   AAAAA
M M M M  E      G     G  A   A
M  M  M  E      G        A   A
M     M  EEEE   G  GGG   AAAAA
M     M  E      G    G   A   A
M     M  E      G    G   A   A
M     M  EEEEE   GGGG    A   A
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
