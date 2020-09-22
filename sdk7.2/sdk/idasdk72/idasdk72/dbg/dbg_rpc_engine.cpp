
#include <network.hpp>

#include "dbg_rpc_engine.h"

//-------------------------------------------------------------------------
dbg_rpc_engine_t::dbg_rpc_engine_t(bool _is_client)
  : rpc_engine_t(_is_client),
    has_pending_event(false),
    poll_debug_events(false)
{
}

//--------------------------------------------------------------------------
// sends a request and waits for a reply
// may occasionally send another request based on the reply
rpc_packet_t *dbg_rpc_engine_t::send_request_and_receive_reply(bytevec_t &req, int flags)
{
  bool displayed = false;
  rpc_packet_t *result = NULL;

  while ( true )
  {
    if ( displayed && user_cancelled() )
      req = prepare_rpc_packet(RPC_CANCELLED);

    if ( !req.empty() )
    {
      int code = send_data(req);
      if ( code != 0 || (flags & PREQ_GET_EVENT) != 0 )
        break;

      rpc_packet_t *reqp = (rpc_packet_t *)req.begin();
      if ( reqp->code == RPC_ERROR )
        qexit(1); // sent error packet, may die now
    }

    rpc_packet_t *rp = recv_packet();
    if ( rp == NULL )
      break;

    switch ( rp->code )
    {
      case RPC_UNK:
        dwarning("rpc: remote did not understand our request");
        goto FAILURE;
      case RPC_MEM:
        dwarning("rpc: no remote memory");
        goto FAILURE;
      case RPC_CANCELLED:
        msg("rpc: user cancelled the operation\n");
        goto FAILURE;
      case RPC_OK:
        result = rp;
        goto END;
    }

    if ( (flags & PREQ_MUST_LOGIN) != 0 )
    {
      lprintf("Exploit packet has been detected\n");
FAILURE:
      qfree(rp);
      break;
    }

    req = on_send_request_interrupt(rp);
    qfree(rp);
  }

END:
  on_send_request_end(result);

  return result;
}

//-------------------------------------------------------------------------
int dbg_rpc_engine_t::_send_request_get_int_result(bytevec_t &req, int failure_code, qstring *errbuf)
{
  rpc_packet_t *rp = send_request_and_receive_reply(req);
  if ( rp == NULL )
    return failure_code;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  int rc = unpack_dd(&answer, end);
  if ( rc < 0 && errbuf != NULL )
    *errbuf = extract_cstr(&answer, end);

  qfree(rp);
  return rc;
}
