cat > complete_setup.sh << 'EOF'
#!/bin/bash
echo "Setting up Go..."
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

echo "Installing all tools..."
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest  
go install github.com/tomnomnom/anew@latest

echo "Installing urldedupe manually..."
mkdir -p /tmp/tools && cd /tmp/tools
wget -q https://github.com/ameenmaali/urldedupe/releases/download/v1.2.0/urldedupe-linux-amd64-1.2.0.tgz
tar -xzf urldedupe-linux-amd64-1.2.0.tgz
sudo mv urldedupe-linux-amd64-1.2.0 /usr/local/bin/urldedupe
sudo chmod +x /usr/local/bin/urldedupe
cd ~ && rm -rf /tmp/tools

echo "Creating system links..."
sudo ln -sf $HOME/go/bin/* /usr/local/bin/ 2>/dev/null || true

echo "Testing installation..."
katana -version && echo "✓ Katana working"
gau -h >/dev/null 2>&1 && echo "✓ GAU working"  
urldedupe -h >/dev/null 2>&1 && echo "✓ urldedupe working"

echo "Setup complete!"
EOF

chmod +x complete_setup.sh
./complete_setup.sh
