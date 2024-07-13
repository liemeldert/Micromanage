'use client';

import React, { useEffect, useState } from 'react';
import { Box, Heading, Spinner, Tabs, TabList, TabPanels, Tab, TabPanel, Table, Tbody, Td, Th, Thead, Tr } from '@chakra-ui/react';
import { getDevices, getAllDeviceDetails, DeviceShard, Device } from '@/lib/micromdm';
import { useRouter } from 'next/navigation';
import {
  useReactTable,
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  flexRender
} from '@tanstack/react-table';

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<DeviceShard[]>([]);
  const [allDevices, setAllDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const router = useRouter();

  useEffect(() => {
    const fetchDevices = async () => {
      const devices = await getDevices();
      setDevices(devices);
      const allDeviceDetails = await getAllDeviceDetails();
      setAllDevices(allDeviceDetails);
      setLoading(false);
    };

    fetchDevices();
  }, []);

  const columnHelper = createColumnHelper<DeviceShard>();
  const columns = [
    columnHelper.accessor('udid', {
      header: 'UUID',
    }),
    columnHelper.accessor('serial_number', {
      header: 'Serial Number',
    }),
    columnHelper.accessor('model', {
      header: 'Model',
    }),
  ];

  const allDeviceColumnHelper = createColumnHelper<Device>();
  const allDeviceColumns = [
    allDeviceColumnHelper.accessor('UDID', {
      header: 'UDID',
    }),
    allDeviceColumnHelper.accessor('DeviceName', {
      header: 'Device Name',
    }),
    allDeviceColumnHelper.accessor('SerialNumber', {
      header: 'Serial Number',
    }),
    allDeviceColumnHelper.accessor('Model', {
      header: 'Model',
    }),
    allDeviceColumnHelper.accessor('OSVersion', {
      header: 'OS Version',
    }),
  ];

  const mdmTable = useReactTable({
    data: devices,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  const allDevicesTable = useReactTable({
    data: allDevices,
    columns: allDeviceColumns,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  if (loading) {
    return <Spinner />;
  }

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
                  <Tr key={row.id} onClick={() => router.push(`/devices/details/${row.original.UDID}`)}>
                    {row.getVisibleCells().map(cell => (
                      <Td key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </Td>
                    ))}
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </TabPanel>
          
          <TabPanel>
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
                  <Tr key={row.id} onClick={() => router.push(`/devices/details/${row.original.udid}`)}>
                    {row.getVisibleCells().map(cell => (
                      <Td key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </Td>
                    ))}
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </TabPanel>
        </TabPanels>
      </Tabs>
    </Box>
  );
};

export default DeviceList;
