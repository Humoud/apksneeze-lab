#!/usr/bin/env python3.8
# Taken from: https://github.com/GhostManager/Ghostwriter/blob/master/ghostwriter/modules/codenames.py
# Which is based on: https://github.com/and3rson/codename/blob/master/codename/codename.py

from random import choice

ATTRIBUTES = [
    # Environ
    'desert', 'tundra', 'mountain', 'space', 'field', 'urban', 'freerange',
    # Stealth and cunning
    'hidden', 'covert', 'uncanny', 'scheming', 'decisive', 'untouchable',
    'stalking',
    # Volatility
    'rowdy', 'dangerous', 'explosive', 'threatening', 'warring', 'deadly',
    'killer', 'insane', 'wild',
    # Organic Gems and materials
    'amber', 'bone', 'coral', 'ivory', 'jet', 'pearl', 'obsidian', 'glass',
    # Regular Gems
    'beryl', 'diamond', 'ruby', 'onyx', 'sapphire', 'emerald', 'jade',
    # Colors
    'red', 'orange', 'yellow', 'green', 'blue', 'violet',
    # Unsorted
    'draconic', 'wireless', 'spinning', 'falling', 'orbiting', 'hunting',
    'chasing', 'searching', 'revealing', 'flying', 'destroyed',
    'inconceivable', 'tarnished', 'latent', 'sleepy', 'resilient',
    'irresistible', 'phantasmal', 'planar', 'minor', 'major', 'greater',
    'compelling', 'foolish', 'mad', 'intelligent', 'jovial', 'hideous',
    'honorable', 'hardy', 'craven', 'doomed', 'rugged', 'blazing', 'zombified'
]

OBJECTS = [
    # Animals
    'panther', 'wildcat', 'tiger', 'lion', 'cheetah', 'cougar', 'leopard',
    'dingo', 'pangolin', 'yak', 'ocelot', 'narwhal', 'koala', 'grizzly',
    'falcon', 'raven', 'owl', 'wolf', 'boar', 'gopher', 'bloodhound'
    # Reptiles
    'viper', 'cottonmouth', 'python', 'boa', 'sidewinder', 'cobra',
    # Sea life
    'octopus', 'lobster', 'crab', 'hammerhead', 'orca', 'piranha',
    'cuttlefish', 'shark',
    # Mythical creatures
    'mermaid', 'unicorn', 'fairy', 'troll', 'yeti', 'pegasus', 'griffin',
    'dragon', 'elf', 'dwarf', 'halfing', 'imp', 'amarok', 'wendigo',
    'basilisk', 'yeti', 'chimera', 'kraken', 'hydra', 'dropbear',
    # Occupations
    'nomad', 'wizard', 'cleric', 'necromancer', 'paladin', 'ranger', 'rogue',
    'warlock', 'bard', 'druid', 'monk', 'fighter', 'warrior', 'adept',
    # Technology
    'robot', 'android', 'cyborg', 'display', 'battery', 'memory', 'disk',
    # Weather
    'storm', 'thunder', 'lightning', 'sun', 'drought', 'snow', 'drizzle',
    # Other
    'presence', 'player', 'cup', 'chain', 'souffle', 'beam', 'analyst', 'glee',
    'toll', 'tarmac', 'enigma'
]


def codename(capitalize=False, uppercase=False, separator=' '):
    """Generate and return a codename consisting of adjective and noun."""
    words = [choice(ATTRIBUTES), choice(OBJECTS)]
    if capitalize:
        words = list(map(str.capitalize, words))
    if uppercase:
        words = list(map(str.upper, words))
    return separator.join(words)
