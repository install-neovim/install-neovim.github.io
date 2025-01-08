sudo EBIAN_FRONTEND=noninteractive apt install zsh -y
sh -c "$(curl -fsSL https://install.ohmyz.sh/)"
git clone https://kkgithub.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions)/g' .zshrc
