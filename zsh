sudo EBIAN_FRONTEND=noninteractive apt install zsh git command-not-found -y
sh -c "$(curl -fsSL https://install.ohmyz.sh/)"
# 对于国内环境，这里应该在 curl 前添加 proxychains4 使用代理，或者使用 githubfast 镜像下载 zsh-install.sh
# sh -c "$(curl -fsSL https://install-neovim.github.io/ref/zsh-install.sh | sed 's/github.com/githubfast.com/g')"
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions)/g' ~/.zshrc

# For tmux 
# echo -e "\nset-option -g default-shell $(which zsh)" >> ~/.tmux.conf
# echo -e "\nset-option -g default-command \"zsh -l\"" >> ~/.tmux.conf

echo -e "\nexport LC_ALL=en_US.UTF-8" >> ~/.zshrc
echo -e "\nexport LANG=en_US.UTF-8" >> ~/.zshrc
echo "source /etc/zsh_command_not_found" >> ~/.zshrc

# Cancel update check
# echo "DISABLE_AUTO_UPDATE=\"true\"" >> $ZSH/oh-my-zsh.sh
