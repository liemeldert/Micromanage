import {useEffect, useState} from "react";
import {ITenant} from "@/lib/tenant";

export const useTenant = () => {
    const [tenant, setTenant] = useState<ITenant | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchTenant = async () => {
            setLoading(true);
            setError(null);

            const tenant_id = localStorage.getItem('selectedTenant');
            if (!tenant_id) {
                setError('No tenant selected');
                setLoading(false);
                return;
            }

            try {
                const response = await fetch(`/${tenant_id}/api/get_tenant`);
                if (!response.ok) {
                    throw new Error('Failed to fetch tenant');
                }
                const data: ITenant = await response.json();
                setTenant(data);
            } catch (err) {
                if (err instanceof Error) {
                    setError(err.message);
                } else {
                    setError('An unknown error occurred');
                }
            } finally {
                setLoading(false);
            }
        };

        fetchTenant();
    }, []);

    return {tenant, loading, error};
};