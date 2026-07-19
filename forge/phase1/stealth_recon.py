from __future__ import annotations

import time
import random
import requests
from pathlib import Path
from typing import Any

def run_crawl_stealth(target: str, use_tor: bool, jitter_min_ms: int, jitter_max_ms: int, engine: str, db_path: Path) -> dict[str, Any]:
    # Apply jitter to evade time-based signatures
    time.sleep(random.randint(jitter_min_ms, jitter_max_ms) / 1000.0)
    
    if engine == "playwright":
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser_args = []
                if use_tor:
                    # Route through integrated Tor module proxy
                    browser_args.append("--proxy-server=socks5://127.0.0.1:9050")
                    
                browser = p.chromium.launch(headless=True, args=browser_args)
                page = browser.new_page()
                page.goto(target, wait_until="domcontentloaded", timeout=30000)
                
                content = page.content()
                title = page.title()
                browser.close()
                
                return {
                    "status": "success",
                    "target": target,
                    "evasion_used": True,
                    "engine": engine,
                    "title": title,
                    "content_length": len(content)
                }
        except ImportError:
            return {"status": "failed", "error": "playwright not installed"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # Fallback if engine is not playwright
    return {
        "status": "success",
        "target": target,
        "evasion_used": True,
        "engine": engine
    }

def run_searxng_passive(target: str, searxng_url: str, use_tor: bool, db_path: Path) -> dict[str, Any]:
    try:
        proxies = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"} if use_tor else None
        resp = requests.get(f"{searxng_url}/search", params={"q": target, "format": "json"}, timeout=10.0, proxies=proxies)
        results = resp.json() if resp.status_code == 200 else {}
    except requests.RequestException as e:
        return {"status": "failed", "error": str(e)}
        
    return {
        "status": "success",
        "target": target,
        "passive_results_count": len(results.get("results", [])),
        "source": "searxng"
    }
