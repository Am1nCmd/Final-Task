// ---- Exploit

Initialize parameters and offsets for the exploit.

1. Create the thread whose ith_voucher field we will use during the exploit. This could be the current thread, but that causes a panic if we try to perform logging while not being run under a debugger, since write() will trigger an access to ith_voucher. To avoid this, we create a separate thread whose ith_voucher field we can control. In order for thread_set_mach_voucher() to work, we need to be sure not to start the thread.

2. Create some pipes so that we can spray pipe buffers later. We'll be limited to 16 MB of pipe memory, so don't bother creating more.

3. Spray a bunch of IPC ports. Hopefully these ports force the ipc.ports zone to grow and allocate fresh pages from the zone map, so that the pipe buffers we allocate next are placed directly after the ports.

We want to do this as early as possible so that the ports are given low addresses in the zone map, which increases the likelihood that bits 28-31 of the pointer are 0 (which is necessary later so that the overlapping iv_refs field of the voucher is valid).

Grab the base port.

Bump the queue limit on the first 2000 ports, which will also be used as holding ports.

    4. Spray our pipe buffers. We're hoping that these land contiguously right after the ports.

    For each pipe buffer we're going to spray, initialize the possible ipc_ports so that the IKOT_TYPE tells us which pipe index overlaps. We have 1024 pipes and 12 bits of IKOT_TYPE data, so the pipe index should fit just fine.

5. Spray IPC vouchers. After we trigger the vulnerability to get a dangling voucher pointer, we can trigger zone garbage collection and get them reallocated with our OOL ports spray.

Assume we'll need 300 early vouchers, 6 transition blocks, 4 target block, and 6 late blocks.

6. Spray 15% of memory (400MB on the iPhone XR) in kalloc.1024 that we can free later to prompt gc. We'll reuse some of the early ports from the port spray above for this.

7. Stash a pointer to an ipc_voucher in the thread's ith_voucher field and then remove the added reference. That way, when we deallocate the voucher ports later, we'll be left with a dangling voucher pointer in ith_voucher.

8. Create the OOL ports pattern that we will spray to overwrite the freed voucher.

We will reallocate the voucher to kalloc.32768, which is a convenient size since it lets us very easily predict what offsets in the allocation correspond to which fields of the voucher.

Now, walk though and initialize the "vouchers" in the ool_ports array.

Send an OOL port one pointer past the start of the voucher. This will cause the port pointer to overlap the voucher's iv_refs field, allowing us to use the voucher port we'll get from thread_get_mach_voucher() later without panicking. This port plays double-duty since we'll later use the reference count bug again to increment the refcount/port pointer to point into our pipe buffer spray, giving us a fake port.

Leave the voucher's iv_port field (index 7) as MACH_PORT_NULL, so that we can call thread_get_mach_voucher() to get a new voucher port that references this voucher. This is what allows us to manipulate the reference count later to change the OOL port set above.

9. Free the first GC spray. This makes that memory available for zone garbage collection in the loop below.

10. Free the vouchers we created earlier. This leaves a voucher pointer dangling in our thread's ith_voucher field. The voucher ports we created earlier are all now invalid.

The voucher objects themselves have all been overwritten with 0xdeadbeefdeadbeef. If we call thread_get_mach_voucher() here, we'll get an "os_refcnt: overflow" panic, and if we call thread_set_mach_voucher() to clear it, we'll get an "a freed zone element has been modified in zone ipc vouchers" panic.

11. Reallocate the freed voucher with the OOL port pattern created earlier in the kalloc.32768 zone. We need to do this slowly in order to force a zone garbage collection. Spraying 17% of memory (450 MB on the iPhone XR) with OOL ports should be plenty.

Use at most 500 ports for the spray.

12. Once we've reallocated the voucher with an OOL ports allocation, the iv_refs field  will overlap with the lower 32 bits of the pointer to base_port. If base_port's address is low enough, this tricks the kernel into thinking that the reference count is valid, allowing us to call thread_get_mach_voucher() without panicking. And since the OOL ports pattern overwrote the voucher's iv_port field with MACH_PORT_NULL, convert_voucher_to_port() will go ahead and allocate a fresh voucher port through which we can manipulate our freed voucher while it still overlaps our OOL ports.

13. Alright, we've pushed through the first risky part! We now have a voucher port thatrefers to a voucher that overlaps with our OOL ports spray. Our next step is to modifythe voucher's iv_refs field using the reference counting bugs so that the ipc_port pointer it overlaps with now points into our pipe buffers. That way, when we receive the message, we'll get a send right to a fake IPC port object whose contents we control.

This is a horrible fix, since ith_voucher still points to the freed voucher, but at least it'll make the OOL port pointer correct so the exploit can continue.

14. Now receive the OOL ports and recover our voucher port and the fake port that overlaps our pipe buffers. This is where we're most likely to panic if the port/pipe groom failed and the overlapping OOL port pointer does not point into our pipe buffers.

Loop through each of the possible voucher positions in the OOL ports looking for a sign that this is where the voucher overlaps.

We're checking to see whether index 7 (which was MACH_PORT_NULL when we sent the message) now contains a port. If it does, that means that this segment of the OOL ports overlapped with the freed voucher, and so when we called thread_get_mach_voucher() above, the iv_port field was set to the newly allocated voucher port (which is what we're receiving now).

Make sure we got a fake port.

15. Check which pair of pipefds overlaps our port using mach_port_kobject(). The returned type value will be the lower 12 bits of the ipc_port's ip_bits field, which we've set to the index of the pipe overlapping the port during our spray.

This is the third and final risky part: we could panic if our fake port doesn't actually point into our pipe buffers. After this, though, it's all smooth sailing.

Get the pipefds that allow us to control the port.

16. Clean up unneeded resources: terminate the ith_voucher thread, discard the filler ports, and close the sprayed pipes.

17. Use mach_port_request_notification() to put a pointer to an array containing base_port in our port's ip_requests field.

18. Now read back our pipe buffer to discover the value of ip_requests (and get our first kernel pointer!). This also tells us where our port is located inside the pipe buffer.

We've found the overlapping port. Record the offset of the fake port, save the ip_requests array, and set the field in the port to NULL.

Clear out all the other fake ports.

Make sure we found it.

Do a write so that the stage0 and stage1 read primitives can start with a pipe read.

19. Now that we know the address of an array that contains a pointer to base_port, we need a way to read data from that address so we can locate our pipe buffer in memory.

We'll use the traditional pid_for_task() technique to read 4 bytes of kernel memory. However, in order for this technique to work, we need to get a fake task containing an offset pointer to the address we want to read at a known location in memory. We can do that by initializing our fake port, sending a Mach message containing our fake task to the port, and reading out the port's imq_messages field.

An unfortunate consequence of this technique is that each 4-byte read leaks an ipc_kmsg allocation. Thus, we'll store the leaked kmsgs so that we can deallocate them later.

Check that it has the offset that we expect.

20. Now use base_port_address to compute the address of the fake port and the containing pipe buffer, and choose an offset for our fake task in the pipe buffer as well. At this point, we can now use our stage 1 read primitive.

21. Now that we have the address of our pipe buffer, we can use the stage 1 read primitive. Get the address of our own task port, which we'll need later.

22. Our next goal is to build a fake kernel_task port that allows us to read and write kernel memory with mach_vm_read()/mach_vm_write(). But in order to do that, we'll first need to get ipc_space_kernel and kernel_map. We'll use Ian's technique from multi_path for this.

First things first, get the address of the host port.

23. We can get ipc_space_kernel from the host port's ip_receiver.

24. Now we'll iterate through all the ports in the host port's block to try and find the kernel task port, which will give us the address of the kernel task.

Make sure we got the kernel_task's address.

25. Next we can use the kernel task to get the address of the kernel vm_map.

26. Build a fake kernel task port that allows us to read and write kernel memory.

27. Alright, now kernel_read() and kernel_write() should work, so let's build a safer kernel_task port. This also cleans up fake_port so that we (hopefully) won't panic on exit.

28. We've corrupted a bunch of kernel state, so let's clean up our mess:
- base_port has an extra port reference.
- uaf_voucher_port needs to be destroyed.
- ip_requests needs to be deallocated.
- leaked_kmsgs need to be destroyed.

29. And finally, deallocate the remaining unneeded (but non-corrupted) resources.

And that's it! Enjoy kernel read/write via kernel_task_port.
