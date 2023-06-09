# Copyright (C) 2020-2022 Hatching B.V
# All rights reserved.

class Paginator:
    def __init__(self, client, path, max):
        self._client = client
        self._path = path
        self._offset = None
        self._limit = 200
        self._current_page = []
        self._eof = False
        self._max = int(max)
        self._counter = 0

    def __iter__(self):
        return self

    def _fetch_next_page(self):
        if '?' in self._path:
            path = self._path + '&'
        else:
            path = self._path + '?'

        if self._max < self._limit:
            self._limit = self._max

        path = path + 'limit={0}'.format(self._limit)
        if self._offset is not None:
            path = path + '&offset={0}'.format(self._offset)

        resp = self._client._req_json('GET', path)

        if resp.get('next'):
            self._offset = resp['next']
        else:
            self._offset = None
            self._eof = True

        self._current_page = resp['data'] or []

        return len(self._current_page) > 0

    def __next__(self):
        if self._counter == self._max:
            raise StopIteration

        if len(self._current_page) == 0:
            if self._eof:
                raise StopIteration
            if not self._fetch_next_page():
                raise StopIteration

        self._counter += 1
        return self._current_page.pop(0)
