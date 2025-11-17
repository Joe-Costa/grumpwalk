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

# Detect shell
SHELL_NAME=$(basename "$SHELL")
echo "Detected shell: $SHELL_NAME"
echo

# Generate the completion command
COMPLETION_CMD="eval \"\$(register-python-argcomplete $GRUMPWALK_PATH)\""

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
        return 0
    fi

    # Add completion configuration
    echo "" >> "$config_file"
    echo "$marker" >> "$config_file"
    echo "$COMPLETION_CMD" >> "$config_file"
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
echo "    $GRUMPWALK_PATH --ho<TAB>"
echo "    $GRUMPWALK_PATH --type <TAB>"
