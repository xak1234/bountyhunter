#!/usr/bin/env python3

import subprocess
import os
import platform

def check_tool_debug(tool_name):
    """Check if a tool is available with detailed debugging"""
    print(f"\n🔍 Testing {tool_name}:")
    
    try:
        if tool_name == 'go':
            cmd = [tool_name, "version"]
            print(f"  Command: {cmd}")
            result = subprocess.run(cmd, capture_output=True, timeout=10)
        else:
            cmd = [tool_name, "-h"]
            print(f"  Command: {cmd}")
            result = subprocess.run(cmd, capture_output=True, timeout=10)
        
        print(f"  Return code: {result.returncode}")
        print(f"  Stdout: {result.stdout[:100]}...")
        print(f"  Stderr: {result.stderr[:100]}...")
        
        success = result.returncode == 0
        print(f"  Result: {'✅ SUCCESS' if success else '❌ FAILED'}")
        return success
        
    except Exception as e:
        print(f"  Exception: {str(e)}")
        print(f"  Result: ❌ FAILED")
        return False

def test_tools_debug():
    """Test tools with detailed debugging"""
    print("🔍 Debug Tool Recognition")
    print("=" * 60)
    
    tools = ['amass', 'httpx', 'gau', 'waybackurls', 'nuclei']
    
    for tool in tools:
        check_tool_debug(tool)
    
    print("\n" + "=" * 60)
    print("Debug complete!")

if __name__ == "__main__":
    test_tools_debug() 