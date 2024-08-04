'use client';

import React, {useEffect, useState} from 'react';
import {
  Box,
  Button,
  Checkbox,
  Heading,
  HStack,
  Input,
  Menu,
  MenuButton,
  MenuItem,
  MenuList,
  Spinner,
  Tab,
  Table,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  VStack
} from '@chakra-ui/react';
import {Device, DeviceShard, getAllDeviceDetails, getDevices} from '@/lib/micromdm';
import {useRouter} from 'next/navigation';
import {
  ColumnDef,
  ColumnOrderState,
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import {ChevronDownIcon} from '@chakra-ui/icons';
import {useTenant} from "@/lib/useTenant";
import CenterCard from "@/app/components/CenterCard";

const DeviceList: React.FC = () => {
    const [devices, setDevices] = useState<DeviceShard[]>([]);
    const [allDevices, setAllDevices] = useState<Device[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [globalFilter, setGlobalFilter] = useState<string>('');
    const [columnOrder, setColumnOrder] = useState<ColumnOrderState>([]);
    const [columnVisibility, setColumnVisibility] = useState({});

    const router = useRouter();
    const tenant = useTenant();

    useEffect(() => {
        const fetchDevices = async () => {
            if (!tenant?.tenant?._id || !allDevices) {
                console.error('Tenant ID is undefined');
                return;
            }
            try {
                const devices = await getDevices(tenant.tenant._id);
                setDevices(devices);
                const allDeviceDetails = await getAllDeviceDetails(tenant.tenant._id);
                setAllDevices(allDeviceDetails);
                return;
            } catch (error) {
                console.error('Error fetching devices:', error);
            } finally {
                setLoading(false);
            }
        };

        if (!tenant.loading && tenant.tenant) {
            fetchDevices();
        }
    }, [tenant.loading, tenant.tenant?._id]);

    const columnHelperShard = createColumnHelper<DeviceShard>();
    // yes this is bad, but I don't think that there's anything that I can really do about it.
    const columns: ColumnDef<DeviceShard>[] = [
        // @ts-ignore
        columnHelperShard.accessor('udid', {
            header: 'UUID',
        }),
        // @ts-ignore
        columnHelperShard.accessor('serial_number', {
            header: 'Serial Number',
        }),
        // @ts-ignore
        columnHelperShard.accessor('model', {
            header: 'Model',
        }),
    ];

    const columnHelperDevice = createColumnHelper<Device>();
    const allDeviceColumns: ColumnDef<Device>[] = [
        // @ts-ignore
        columnHelperDevice.accessor('SerialNumber', {
            header: 'Serial Number',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('DeviceName', {
            header: 'Device Name',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('ProductName', {
            header: 'Product Identifier',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('Model', {
            header: 'Model',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('OSVersion', {
            header: 'OS Version',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('UDID', {
            header: 'UDID',
        }),
    ];

    const mdmTable = useReactTable({
        data: devices,
        columns,
        state: {
            columnOrder,
            columnVisibility,
            globalFilter,
        },
        onColumnOrderChange: setColumnOrder,
        onColumnVisibilityChange: setColumnVisibility,
        onGlobalFilterChange: setGlobalFilter,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
    });

    const allDevicesTable = useReactTable({
        data: allDevices,
        columns: allDeviceColumns,
        state: {
            columnOrder,
            columnVisibility,
            globalFilter,
        },
        onColumnOrderChange: setColumnOrder,
        onColumnVisibilityChange: setColumnVisibility,
        onGlobalFilterChange: setGlobalFilter,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
    });

    if (loading) {
        return (
            <>
                <Spinner/>
            </>
        );
    } else if (!allDevices) {
        return (
            <>
                <CenterCard>
                    <Heading>No devices have responded to requests for information.</Heading>
                    <Text>Not what you're expecting to see?</Text>
                    <Text>Check your profiles and network connections on each device.</Text>
                </CenterCard>
            </>
        )
    }

    // @ts-ignore
    const renderColumnToggle = (table: any) => (
        <Menu>
            <MenuButton as={Button} rightIcon={<ChevronDownIcon/>}>
                Toggle Columns
            </MenuButton>
            <MenuList>
                {
                    // @ts-ignore
                    table.getAllLeafColumns().map(column => (
                        <MenuItem key={column.id}>
                            <Checkbox
                                isChecked={column.getIsVisible()}
                                onChange={column.getToggleVisibilityHandler()}
                            >
                                {column.id}
                            </Checkbox>
                        </MenuItem>
                    ))}
            </MenuList>
        </Menu>
    );

    return (
        <Box>
            <Heading as="h1" size="lg" mb={4}>Device List</Heading>
            <Tabs>
                <TabList>
                    <Tab>Checked-in Devices</Tab>
                    <Tab>MDM Devices</Tab>
                </TabList>

                <TabPanels>
                    <TabPanel>
                        <VStack align="start" mb={4}>
                            <HStack>
                                <Input
                                    placeholder="Search..."
                                    value={globalFilter ?? ''}
                                    onChange={e => setGlobalFilter(e.target.value)}
                                />
                                {renderColumnToggle(allDevicesTable)}
                            </HStack>
                            <Table>
                                <Thead>
                                    {allDevicesTable.getHeaderGroups().map(headerGroup => (
                                        <Tr key={headerGroup.id}>
                                            {headerGroup.headers.map(header => (
                                                <Th key={header.id}>
                                                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                                                </Th>
                                            ))}
                                        </Tr>
                                    ))}
                                </Thead>
                                <Tbody>
                                    {allDevicesTable.getRowModel().rows.map(row => (
                                        <Tr key={row.id}
                                            onClick={() => router.push(`/${tenant?.tenant?._id}/devices/details/${row.original.UDID}`)}>
                                            {row.getVisibleCells().map(cell => (
                                                <Td key={cell.id}>
                                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                                </Td>
                                            ))}
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </VStack>
                    </TabPanel>

                    {/* MDM Devices Tab */}
                    <TabPanel>
                        <VStack align="start" mb={4}>
                            <HStack>
                                <Input
                                    placeholder="Search..."
                                    value={globalFilter ?? ''}
                                    onChange={e => setGlobalFilter(e.target.value)}
                                />
                                {renderColumnToggle(mdmTable)}
                            </HStack>
                            <Table>
                                <Thead>
                                    {mdmTable.getHeaderGroups().map(headerGroup => (
                                        <Tr key={headerGroup.id}>
                                            {headerGroup.headers.map(header => (
                                                <Th key={header.id}>
                                                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                                                </Th>
                                            ))}
                                        </Tr>
                                    ))}
                                </Thead>
                                <Tbody>
                                    {mdmTable.getRowModel().rows.map(row => (
                                        <Tr key={row.id}
                                            onClick={() => router.push(`/${tenant?.tenant?._id}/devices/details/${row.original.udid}`)}>
                                            {row.getVisibleCells().map(cell => (
                                                <Td key={cell.id}>
                                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                                </Td>
                                            ))}
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </VStack>
                    </TabPanel>
                </TabPanels>
            </Tabs>
        </Box>
    );
};

export default DeviceList;
