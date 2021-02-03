use vm_memory::{GuestMemoryMmap, GuestAddress, Bytes, GuestMemory};
use vhost_gpu_backend::{VirtioGpuCommandResult, RutabagaIovec, RutabagaFenceData};
use vhost_gpu_backend::protocol::VIRTIO_GPU_FLAG_INFO_FENCE_CTX_IDX;
use std::os::raw::c_void;
use crate::virtio::gpu::{Error, Result};

pub fn decode_gpu_cmd(
    cmd: &GuestMemoryMmap,
    addr: GuestAddress
) -> VirtioGpuCommandResult  {
    use vhost_gpu_backend::protocol::VirtioGpuCommand::*;
    use vhost_gpu_backend::protocol::VirtioGpuCommandDecodeError;
    use vhost_gpu_backend::protocol::*;

    let hdr = cmd.read_obj::<virtio_gpu_ctrl_hdr>(addr)?;
    Ok(match hdr.type_.into() {
        VIRTIO_GPU_CMD_GET_DISPLAY_INFO         => CmdGetDisplayInfo(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_CREATE_2D       => CmdResourceCreate2D(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_UNREF           => CmdResourceUnref(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D      => CmdTransferToHost2D(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_SET_SCANOUT              => CmdSetScanout(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_FLUSH           => CmdResourceFlush(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING  => CmdResourceAttachBacking(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING  => CmdResourceDetachBacking(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_GET_CAPSET_INFO          => CmdGetCapsetInfo(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_GET_CAPSET               => CmdGetCapset(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_GET_EDID                 => CmdGetEdid(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID     => CmdResourceAssignUuid(cmd.read_obj(addr)?),

        VIRTIO_GPU_CMD_CTX_CREATE               => CmdCtxCreate(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_CTX_DESTROY              => CmdCtxDestroy(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE      => CmdCtxAttachResource(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE      => CmdCtxDetachResource(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_RESOURCE_CREATE_3D       => CmdResourceCreate3D(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D      => CmdTransferToHost3D(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D    => CmdTransferFromHost3D(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_SUBMIT_3D                => CmdSubmit3D(cmd.read_obj(addr)?),

        VIRTIO_GPU_CMD_UPDATE_CURSOR            => CmdUpdateCursor(cmd.read_obj(addr)?),
        VIRTIO_GPU_CMD_MOVE_CURSOR              => CmdMoveCursor(cmd.read_obj(addr)?),

        type_ => return Err(VirtioGpuCommandDecodeError::InvalidCommand(type_)),
    })
}


pub(crate) fn sglist_to_rutabaga_iovecs(vecs: &[(GuestAddress, usize)], mem: &GuestMemoryMmap) -> Result<Vec<RutabagaIovec>> {
    // validate sglist range
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice(addr, len).is_err()) {
        return Err(Error::InvalidSglistRegion);
    }

    let mut iovecs: Vec<RutabagaIovec> = Vec::new();
    for &(addr, len) in vecs {
        // it is safe to unwrap host address because we have already checked
        let address = mem.get_host_address(addr).unwrap();
        iovecs.push(RutabagaIovec {
            base: address as *mut c_void,
            len,
        })
    }

    Ok(iovecs)
}

pub(crate) fn fence_ctx_equal(desc_fence: &RutabagaFenceData, completed: &RutabagaFenceData) -> bool {
    let desc_fence_ctx = desc_fence.flags & VIRTIO_GPU_FLAG_INFO_FENCE_CTX_IDX != 0;
    let completed_fence_ctx = completed.flags & VIRTIO_GPU_FLAG_INFO_FENCE_CTX_IDX != 0;

    // Both fences on global timeline -- only case with upstream kernel.  The rest of the logic
    // is for per fence context prototype.
    if !completed_fence_ctx && !desc_fence_ctx {
        return true;
    }

    // One fence is on global timeline
    if desc_fence_ctx != completed_fence_ctx {
        return false;
    }

    // Different 3D contexts
    if desc_fence.ctx_id != completed.ctx_id {
        return false;
    }

    // Different fence contexts with same 3D context
    if desc_fence.fence_ctx_idx != completed.fence_ctx_idx {
        return false;
    }

    true
}