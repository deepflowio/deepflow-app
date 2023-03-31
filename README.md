# deepflow-app
DeepFlow-app is based on the DeepFlow visibility platform, providing the ability to call the link trace function

## background and premise

DeepFlow stores the details related to system calls and network calls in Log Event format, and there are three kinds of data according to the Flow `type` classification:
- a single request for Event data.
- a single response to Event data.
- A session event data, this type of data conforms to the basic definition of Span-like data.

So, here is to convert the existing Flow Log Event into Span-like data, that is: merge the request and response data in the flow `type` into the seesion data, and merge and sort with the session data belonging to the same call, and convert it into a call Span-like data in stack order.

## How to construct Span-like data

- Query all related Flow Log Events based on `_id`.
  - Use tcp_seq to query net spans.
  - Query sys span using syscall_trace_id.
  - Query app span(APM) data with trace_id, span_id, parent_span_id, x_request_id.
- Merge request and response data into seesion data and construct Span-like data.
- Sort the merged data and build Span-like data that conforms to the call stack.

## Others
For details, please refer to [here](#)


