import React, {useEffect, useState} from 'react';
import {Box, Button, Code, Collapse, Heading, Text} from '@chakra-ui/react';
import {getWebhookEvents} from '@/lib/micromdm';
import {useParams} from "next/navigation";

const WebhookEvents: React.FC<{ udid: string }> = ({udid}) => {
    const [events, setEvents] = useState<any[]>([]);
    const [expanded, setExpanded] = useState<number | null>(null);

    const {tenant} = useParams() as { tenant: string };

    useEffect(() => {
        const fetchEvents = async () => {
            const fetchedEvents = await getWebhookEvents(tenant, udid);
            setEvents(fetchedEvents);
        };

        fetchEvents();
    }, [udid]);

    const toggleExpand = (index: number) => {
        setExpanded(expanded === index ? null : index);
    };

    return (
        <Box mt={5}>
            <Heading size="md">Webhook Events</Heading>
            {events.map((event, index) => (
                <Box key={index} mt={3} p={3} borderWidth="1px" borderRadius="md" width="100%">
                    <Text>Topic: {event.topic}</Text>
                    <Text>Time: {new Date(event.created_at).toLocaleString()}</Text>
                    <Text>Status: {event.acknowledge_event.status}</Text>
                    <Button size="sm" mt={2} onClick={() => toggleExpand(index)}>
                        {expanded === index ? 'Collapse' : 'Expand'}
                    </Button>
                    <Collapse in={expanded === index} animateOpacity>
                        <Code mt={2} p={2} width="100%" overflowX="auto" whiteSpace="pre">
                            {JSON.stringify(event, null, 2)}
                        </Code>
                    </Collapse>
                </Box>
            ))}
        </Box>
    );
};

export default WebhookEvents;
