#!/bin/python3
import os


with open("/var/log/apt/history.log") as f:
    history_log = f.read()[1:]

history_list = history_log.split("\n\n")

i = 0
check_string = "Num\tDate\tCommand\n"
for history in history_list:
    date = history.split("\n")[0]
    command = history.split("\n")[1]
    if " install " in command:
        check_string += f'{i}:\t{date.split(": ")[-1]}\t{command.split(": ")[-1]}\n'
    i += 1

print(check_string)

num = input("请选择你想清理哪条命令产生的垃圾（输入序号即可）：")

history = history_list[int(num)]
packages = history.split("\n")[2]
raw_pac = packages.split("),")

# Extract package_list from raw_pac


def extract(x):
    return x.split(" ")[1].split(":")[0]


package_list = list(map(extract, raw_pac))

# Combine the purge command
package_string = ""
for pac in package_list:
    package_string += f" {pac}"

os.system(f"sudo DEBIAN_FRONTEND=noninteractive apt purge {package_string}")

# Remove all orphan package
os.system("sudo DEBIAN_FRONTEND=noninteractive apt install deborphan -y")
os.system("deborphan | xargs sudo DEBIAN_FRONTEND=noninteractive apt purge")

os.system("sudo DEBIAN_FRONTEND=noninteractive apt autoremove -y")
os.system("sudo apt autoclean")
os.system("sudo apt-get clean")

# Clean config files of the removed apps
garb = os.popen("dpkg -l | grep '^rc'").read()
if garb != "":
    os.system("sudo dpkg --purge $(dpkg -l | awk '/^rc/ {print $2}')")
