import { useState, useEffect, useCallback } from 'react'

interface UseApiState<T> {
  data: T | null
  loading: boolean
  error: Error | null
}

export function useApi<T>(
  fetchFn: () => Promise<T>,
  deps: unknown[] = []
): UseApiState<T> & { refetch: () => void } {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: true,
    error: null,
  })

  const fetchData = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }))
    try {
      const data = await fetchFn()
      setState({ data, loading: false, error: null })
    } catch (error) {
      setState({ data: null, loading: false, error: error as Error })
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return { ...state, refetch: fetchData }
}

export function useMutation<T, P = void>(
  mutationFn: (params: P) => Promise<T>
): {
  mutate: (params: P) => Promise<T>
  loading: boolean
  error: Error | null
  data: T | null
} {
  const [state, setState] = useState<{
    loading: boolean
    error: Error | null
    data: T | null
  }>({
    loading: false,
    error: null,
    data: null,
  })

  const mutate = useCallback(
    async (params: P) => {
      setState({ loading: true, error: null, data: null })
      try {
        const data = await mutationFn(params)
        setState({ loading: false, error: null, data })
        return data
      } catch (error) {
        setState({ loading: false, error: error as Error, data: null })
        throw error
      }
    },
    [mutationFn]
  )

  return { ...state, mutate }
}
