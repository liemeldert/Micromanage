import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from controller.models.tenant import Task, Tenant, Device
import logging
import uuid

logger = logging.getLogger(__name__)

class TaskManager:
    """Manages background tasks and operations"""
    
    def __init__(self):
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.task_handlers: Dict[str, Callable] = {}
    
    async def create_task(self, tenant: Tenant, task_type: str, 
                         description: str, device: Optional[Device] = None,
                         user: Optional[str] = None, details: Dict[str, Any] = None) -> Task:
        """Create a new task"""
        task = await Task.create(
            tenant=tenant,
            type=task_type,
            status='pending',
            description=description,
            device=device,
            user=user,
            details=details or {}
        )
        logger.info(f"Created task {task.id}: {description}")
        return task
    
    async def execute_task(self, task: Task, handler: Callable):
        """Execute a task with the given handler.

        The handler (and the deploy helpers it calls) own the task's status. If,
        after the handler returns, the task is 'running' with a command_uuid in
        its details, the command is queued on the device and the WEBHOOK will
        complete/fail it when the device responds -- do not mark it completed
        here. Only synchronous tasks (no command enqueued) complete immediately.
        """
        task_id = str(task.id)

        try:
            # Update task status
            await task.update_progress(0, 'running')

            # Create asyncio task
            async_task = asyncio.create_task(handler(task))
            self.running_tasks[task_id] = async_task

            # Wait for completion
            await async_task

            # Re-read: the handler/deploy path updates the row via separate objects.
            await task.refresh_from_db()
            if task.status in ('pending', 'running') and not (task.details or {}).get('command_uuid'):
                await task.update_progress(100, 'completed')

        except asyncio.CancelledError:
            await task.update_progress(task.progress, 'cancelled')
            raise
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            task.error = str(e)
            await task.update_progress(task.progress, 'failed')
        finally:
            # Remove from running tasks
            self.running_tasks.pop(task_id, None)

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel the in-process asyncio task, if this process is running it.

        Returns whether an in-memory task was cancelled. Callers must still
        cancel the DB row -- tasks created by other processes (sync service) or
        awaiting a device response have no in-memory handle here.
        """
        if task_id in self.running_tasks:
            self.running_tasks[task_id].cancel()
            return True
        return False
    
    async def get_tenant_tasks(self, tenant: Tenant, 
                              status: Optional[str] = None,
                              limit: int = 100) -> List[Task]:
        """Get tasks for a tenant"""
        query = Task.filter(tenant=tenant)
        if status:
            query = query.filter(status=status)
        
        return await query.order_by('-created_at').limit(limit).all()
    
    async def cleanup_old_tasks(self, days: int = 30):
        """Clean up old completed/failed tasks"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        deleted_count = await Task.filter(
            completed_at__lt=cutoff_date,
            status__in=['completed', 'failed', 'cancelled']
        ).delete()
        
        logger.info(f"Cleaned up {deleted_count} old tasks")
        return deleted_count
    
    async def get_task_stats(self, tenant: Tenant) -> Dict[str, Any]:
        """Get task statistics for a tenant"""
        from tortoise.functions import Count
        
        stats = await Task.filter(tenant=tenant).annotate(
            count=Count('id')
        ).group_by('status').values('status', 'count')
        
        return {
            'total': sum(s['count'] for s in stats),
            'by_status': {s['status']: s['count'] for s in stats},
            'running': len([t for t in self.running_tasks.values() if not t.done()])
        }
