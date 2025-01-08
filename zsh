sudo EBIAN_FRONTEND=noninteractive apt install zsh -y
# sh -c "$(curl -fsSL https://install.ohmyz.sh/)"
sh -c "$(curl -fsSL https://install-neovim.github.io/ref/zsh-install.sh | sed 's/github.com/githubfast.com/g')"
git clone https://githubfast.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions)/g' .zshrc

# For tmux 
echo -e "\nset-option -g default-shell $(which zsh)" >> ~/.tmux.conf
