from colorama import init, Fore, Back, Style
from termcolor import colored

init(convert=True)

print(Fore.RED + 'some red text')
print(Back.GREEN + 'and with a green background')
print(Style.DIM + 'and in dim text')
print(Style.RESET_ALL)
print(colored('back to normal now', 'white', 'on_green'))
