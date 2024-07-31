import connectToDatabase from '@/lib/mongodb';
import Tenant from '@/models/tenant';

export interface ITenant {
    _id: string;
    name: string;
    description: string;
    created_at: Date;
    members: string[];
    group_yaml: string;
    webhook_secret: String,
    mdm_url: String,
    mdm_secret: String,
}

export function saveCurrentTenant(tenant: string) {
    localStorage.setItem('selectedTenant', tenant);
};

export async function getCurrentTenant(): Promise<ITenant | null> {
    await connectToDatabase();
    const tenant_id = localStorage.getItem('selectedTenant');
    if (!tenant_id) {
        return null;
    }

    try {
        const tenant = await Tenant.findById(tenant_id).exec();
        if (!tenant) {
            return null;
        }
        return tenant as ITenant;
    } catch (error) {
        console.error('Error fetching tenant:', error);
        return null;
    }
};

