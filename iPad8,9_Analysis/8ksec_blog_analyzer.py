#!/usr/bin/env python3
"""
8kSec Blog Analyzer - Extract iOS Security Research Insights
Analyzes 8ksec.io blog posts for relevant iOS 17.x / A12X information
"""

import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin

def scrape_8ksec_blogs():
    """Scrape all iOS-related blog posts from 8ksec.io"""
    base_url = "https://8ksec.io"

    # Known iOS security blog posts from manual inspection
    known_posts = [
        "https://8ksec.io/analyzing-kernel-panic-ios/",
        "https://8ksec.io/reading-ios-sandbox-profiles/",
        "https://8ksec.io/compiling-dopamine-jailbreak/",
        "https://8ksec.io/patch-diffing-ios-kernel/",
        "https://8ksec.io/mie-deep-dive-kernel/",
        "https://8ksec.io/mie-deep-dive-enabling-apps/",
        "https://8ksec.io/ipsw-walkthrough-part-1-the-swiss-army-knife-for-ios-macos-security-research/",
        "https://8ksec.io/ipsw-walkthrough-part-2-the-swiss-army-knife-for-ios-macos-security-research/",
        "https://8ksec.io/advanced-frida-usage-part-1-ios-encryption-libraries-8ksec-blogs/",
        "https://8ksec.io/ios-deeplink-attacks-part-1-introduction-8ksec-blogs/",
        "https://8ksec.io/advanced-frida-usage-part-2-analyzing-signal-and-telegram-messages-on-ios/",
        "https://8ksec.io/ios-deep-link-attacks-part-2-exploitation-8ksec-blogs/",
        "https://8ksec.io/advanced-frida-usage-part-3-inspecting-ios-xpc-calls/",
        "https://8ksec.io/advanced-frida-usage-part-4-sniffing-location-data-from-locationd-in-ios/",
        "https://8ksec.io/advanced-frida-usage-part-6-utilising-writers/"
    ]

    print("=== 8KSEC.IO iOS SECURITY BLOG ANALYSIS ===\n")
    print(f"Analyzing {len(known_posts)} known iOS blog posts")

    # Analyze each blog post
    relevant_info = []

    for url in known_posts:
        print(f"\nAnalyzing: {url}")
        try:
            post_response = requests.get(url, timeout=10)
            post_soup = BeautifulSoup(post_response.text, 'html.parser')

            # Extract title
            title = post_soup.find('h1')
            title = title.text.strip() if title else "Unknown"

            # Extract content
            content_div = post_soup.find('div', class_='entry-content') or post_soup.find('article')
            content = content_div.get_text() if content_div else ""

            # Search for relevant keywords
            relevant_keywords = [
                'iOS 17', 'A12', 'A12X', 'thread_t', 'task_t', 'tro', 'offset',
                'jailbreak', 'exploit', 'kernel', 'PAC', 'PPL', 'MIE',
                'remote call', 'exception port', 'SpringBoard', 'panic', 'crash',
                'kernelcache', 'dyld', 'codesignature', 'trustcache'
            ]

            found_keywords = []
            for keyword in relevant_keywords:
                if keyword.lower() in content.lower():
                    found_keywords.append(keyword)

            if found_keywords:
                info = {
                    'title': title,
                    'url': url,
                    'keywords': found_keywords,
                    'relevant_content': extract_relevant_snippets(content, found_keywords)
                }
                relevant_info.append(info)
                print(f"  ✅ Relevant: {', '.join(found_keywords)}")

        except Exception as e:
            print(f"  ❌ Error analyzing {url}: {e}")

    return relevant_info

def extract_relevant_snippets(content, keywords):
    """Extract relevant code snippets and technical details"""
    snippets = []

    # Split content into paragraphs
    paragraphs = content.split('\n\n')

    for para in paragraphs:
        para_lower = para.lower()
        if any(kw.lower() in para_lower for kw in keywords):
            # Look for code blocks, offsets, addresses
            if '0x' in para or 'offset' in para_lower or 'struct' in para_lower:
                snippets.append(para.strip())

    return snippets[:5]  # Limit to 5 most relevant

def analyze_for_offsets(relevant_info):
    """Analyze extracted info for potential offsets"""
    print("\n=== OFFSET ANALYSIS FROM 8KSEC BLOGS ===\n")

    offset_patterns = [
        r'0x[0-9a-fA-F]{3,8}',  # Hex addresses/offsets
        r'offset.*?=.*?0x[0-9a-fA-F]+',
        r'struct.*?\{.*?\}',
        r'thread_t.*?:.*?0x[0-9a-fA-F]+',
        r'task_t.*?:.*?0x[0-9a-fA-F]+'
    ]

    found_offsets = []

    for info in relevant_info:
        print(f"From: {info['title']}")
        for snippet in info['relevant_content']:
            for pattern in offset_patterns:
                matches = re.findall(pattern, snippet, re.IGNORECASE)
                if matches:
                    for match in matches:
                        found_offsets.append({
                            'offset': match,
                            'source': info['title'],
                            'context': snippet[:100] + "..."
                        })
                        print(f"  📍 {match}")
                        print(f"     Context: {snippet[:100]}...")

    return found_offsets

def generate_research_summary(relevant_info, found_offsets):
    """Generate comprehensive research summary"""
    summary = f"""
# 8kSec.io iOS Security Research Analysis

## Overview
Analyzed {len(relevant_info)} relevant iOS security blog posts from 8kSec.

## Relevant Blog Posts
"""

    for info in relevant_info:
        summary += f"""
### {info['title']}
**URL:** {info['url']}
**Keywords:** {', '.join(info['keywords'])}

**Key Snippets:**
"""
        for snippet in info['relevant_content'][:3]:
            summary += f"- {snippet[:200]}...\n"

    summary += f"""
## Potential Offsets Found
Found {len(found_offsets)} potential offset/address references:

"""

    for offset in found_offsets:
        summary += f"- `{offset['offset']}` from {offset['source']}\n"
        summary += f"  Context: {offset['context']}\n"

    summary += """
## Research Insights for iPad8,9 iOS 17.3.1

### Key Takeaways:
1. **MIE (Memory Integrity Enforcement)**: Available on A19+ (iPhone 17+), not A12X
2. **PAC Implementation**: A12X has PAC but not the advanced MIE protections
3. **Kernel Structure Changes**: iOS 17 has significant changes in thread/task structures
4. **PPL Protections**: Enhanced in iOS 17, affects jailbreak techniques

### Recommendations:
1. Focus on PAC bypass techniques rather than MIE
2. Study thread_t structure changes in iOS 17
3. Analyze PPL bypass methods for A12X
4. Look into remote call techniques that work with PAC

## Next Steps:
1. Cross-reference found offsets with our kernelcache analysis
2. Study PAC implementation details for A12X
3. Research alternative remote call methods
4. Analyze PPL limitations on A12X devices
"""

    with open('8ksec_research_summary.md', 'w') as f:
        f.write(summary)

    print("Created 8ksec_research_summary.md")

if __name__ == "__main__":
    relevant_info = scrape_8ksec_blogs()
    found_offsets = analyze_for_offsets(relevant_info)
    generate_research_summary(relevant_info, found_offsets)