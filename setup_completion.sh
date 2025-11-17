#!/usr/bin/env bash

# Setup bash/zsh completion for grumpwalk.py
# This script configures argcomplete for the current user without requiring root

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRUMPWALK_PATH="${SCRIPT_DIR}/grumpwalk.py"

echo "Setting up bash completion for grumpwalk.py..."
echo

# Check if grumpwalk.py exists
if [[ ! -f "$GRUMPWALK_PATH" ]]; then
    echo "Error: grumpwalk.py not found at $GRUMPWALK_PATH"
    exit 1
fi

# Ensure ~/.local/bin is in PATH (needed for register-python-argcomplete)
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "Adding ~/.local/bin to PATH for this session..."
    export PATH="$HOME/.local/bin:$PATH"
fi

# Check if argcomplete is installed
if ! python3 -c "import argcomplete" 2>/dev/null; then
    echo "argcomplete is not installed."
    echo
    echo "Installing argcomplete for current user..."
    python3 -m pip install --user argcomplete

    if [[ $? -ne 0 ]]; then
        echo
        echo "Error: Failed to install argcomplete."
        echo "Please install it manually with: python3 -m pip install --user argcomplete"
        exit 1
    fi
    echo "argcomplete installed successfully!"
    echo
fi

# Verify register-python-argcomplete is available
if ! command -v register-python-argcomplete &> /dev/null; then
    echo "Warning: register-python-argcomplete not found in PATH"
    echo "Checking ~/.local/bin..."
    if [[ -f "$HOME/.local/bin/register-python-argcomplete" ]]; then
        echo "Found in ~/.local/bin"
        export PATH="$HOME/.local/bin:$PATH"
    else
        echo "Error: Cannot find register-python-argcomplete executable"
        echo "Please ensure argcomplete is properly installed"
        exit 1
    fi
fi

# Detect shell
SHELL_NAME=$(basename "$SHELL")
echo "Detected shell: $SHELL_NAME"
echo

# Function to add completion to config file
add_to_config() {
    local config_file="$1"
    local marker="# grumpwalk.py argcomplete"

    # Create config file if it doesn't exist
    if [[ ! -f "$config_file" ]]; then
        touch "$config_file"
        echo "Created $config_file"
    fi

    # Check if already configured
    if grep -q "$marker" "$config_file" 2>/dev/null; then
        echo "Completion already configured in $config_file"
        echo "Removing old configuration..."
        # Remove old configuration (from marker to next empty line or EOF)
        # Create a temp file
        local temp_file="${config_file}.tmp"
        local in_section=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == *"$marker"* ]]; then
                in_section=1
                continue
            fi
            if [[ $in_section -eq 1 ]]; then
                # Check if we've reached the end of the section (empty line or new comment)
                if [[ -z "$line" ]] || [[ "$line" =~ ^[^#] ]]; then
                    in_section=0
                    echo "$line" >> "$temp_file"
                fi
                continue
            fi
            echo "$line" >> "$temp_file"
        done < "$config_file"
        mv "$temp_file" "$config_file"
    fi

    # Add completion configuration
    # Support multiple invocation methods
    echo "" >> "$config_file"
    echo "$marker" >> "$config_file"
    echo "# Ensure ~/.local/bin is in PATH (needed for argcomplete)" >> "$config_file"
    echo "if [[ \":\$PATH:\" != *\":\$HOME/.local/bin:\"* ]]; then" >> "$config_file"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$config_file"
    echo "fi" >> "$config_file"
    echo "# Enable argcomplete for grumpwalk.py (supports multiple invocation paths)" >> "$config_file"
    echo "if command -v register-python-argcomplete &> /dev/null; then" >> "$config_file"
    echo "    eval \"\$(register-python-argcomplete grumpwalk.py)\" 2>/dev/null" >> "$config_file"
    echo "    eval \"\$(register-python-argcomplete ./grumpwalk.py)\" 2>/dev/null" >> "$config_file"
    echo "    eval \"\$(register-python-argcomplete $GRUMPWALK_PATH)\" 2>/dev/null" >> "$config_file"
    echo "fi" >> "$config_file"
    echo "Added completion configuration to $config_file"
}

# Configure based on shell
case "$SHELL_NAME" in
    bash)
        # Try .bashrc first, fall back to .bash_profile
        if [[ -f "$HOME/.bashrc" ]]; then
            add_to_config "$HOME/.bashrc"
        elif [[ -f "$HOME/.bash_profile" ]]; then
            add_to_config "$HOME/.bash_profile"
        else
            add_to_config "$HOME/.bashrc"
        fi
        ;;
    zsh)
        add_to_config "$HOME/.zshrc"
        ;;
    *)
        echo "Warning: Unsupported shell '$SHELL_NAME'"
        echo "Please manually add the following to your shell config:"
        echo
        echo "    $COMPLETION_CMD"
        echo
        exit 1
        ;;
esac

echo
echo "Setup complete!"
echo
echo "To activate completion in your current shell, run:"
echo "    source ~/.$SHELL_NAME"rc""
echo
echo "Or start a new terminal session."
echo
echo "Test completion with:"
echo "    grumpwalk.py --ho<TAB>"
echo "    ./grumpwalk.py --type <TAB>"
echo
echo "Note: Completion works with any of these invocation methods:"
echo "  - grumpwalk.py (if in PATH)"
echo "  - ./grumpwalk.py (relative path)"
echo "  - $GRUMPWALK_PATH (absolute path)"
