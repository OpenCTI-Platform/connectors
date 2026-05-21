"""Internal API endpoint constant library.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""

_intelligence_feeds_endpoints = [
  [
    "DownloadFeedArchive",
    "GET",
    "/indicator-feed/entities/feed-download/v1",
    "Downloads the content as a zip archive for a given feed item ID",
    "intelligence_feeds",
    [
      {
        "type": "string",
        "description": "Feed ID",
        "name": "feed_item_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ListFeedTypes",
    "GET",
    "/indicator-feed/entities/feed/v1",
    "Lists the accessible feed types for a given customer",
    "intelligence_feeds",
    []
  ],
  [
    "QueryFeedArchives",
    "GET",
    "/indicator-feed/queries/feed/v1",
    "Queries the accessible feed types for a customer. Returns a list of feed item IDs which can be later downloaded",
    "intelligence_feeds",
    [
      {
        "type": "string",
        "description": "Feed Name",
        "name": "feed_name",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Feed interval must be one of:  dump: Complete historical data snapshot  daily: Daily "
        "aggregated updates  hourly: Hourly incremental updates  minutely: Minute-by-minute updates  any: Automatically "
        " combines the appropriate intervals to provide complete, up-to-date data with minimal overlap\n\nDefaults to "
        "'any' if not specified.",
        "name": "feed_interval",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Since is a valid timestamp in RFC3399 format. Restrictions: minutely: now()-2h, "
        "hourly: now()-2d, daily: now()-5d; dump: now()-7d",
        "name": "since",
        "in": "query"
      }
    ]
  ]
]
