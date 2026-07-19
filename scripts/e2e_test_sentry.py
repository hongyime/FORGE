import sys
import os
from pathlib import Path

# Ensure forge is in path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from forge.config import ForgeConfig
from forge.distributed.coordinator import QueueCoordinator
from forge.webui.command_center import CommandCenterService

def main():
    engagement_id = 1001
    cfg = ForgeConfig.load()
    coordinator = QueueCoordinator(redis_url=cfg.redis_url)
    
    def on_event(ev):
        print(f"Event Emitted: {ev.event_type} - {ev.payload}")
        
    svc = CommandCenterService(
        engagement_id=engagement_id,
        config=cfg,
        coordinator=coordinator,
        publish_event=on_event
    )
    
    # First, enable Sentry
    print("Enabling Sentry...")
    svc.toggle_sentry(True)
    
    state = svc.get_sentry_state()
    print(f"Sentry enabled: {state.enabled}")
    
    print("Calling get_host_context for 10.0.0.10 to trigger Sentry logic...")
    ctx = svc.get_host_context("10.0.0.10")
    
    state = svc.get_sentry_state()
    print(f"Sentry enabled after context generation: {state.enabled}, reason: {state.paused_reason}")

if __name__ == "__main__":
    main()