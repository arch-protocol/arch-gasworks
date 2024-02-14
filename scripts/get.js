import { StatusCodes } from 'http-status-codes';
import axios from 'axios';

/**
 * Generic get function using axios. Headers go inside options. If {retryResponse} is true,
 * axios will try to request again.
 *
 * @param url           The complete url to be requested
 * @param options       Headers and other oprtions passed to axios
 * @param retryResponse If true, will retry the request
 *
 * @returns The api response
 */
export async function get(
  url,
  options,
  retryResponse = false,
) {
  try {
    const api = axios.create();
    if (retryResponse) {
      const maxRetryCount = 2;
      let currentRetryCount = 0;

      const retryRequest = async (
        error,
      ) => {
        const {
          config: originalRequest,
          response: { status },
        } = error;

        if (!originalRequest || currentRetryCount >= maxRetryCount) {
          return Promise.reject(error);
        }
        currentRetryCount += 1;

        if (status && (
          status === StatusCodes.TOO_MANY_REQUESTS
          || status === StatusCodes.INTERNAL_SERVER_ERROR
        )) {
          const delayRetryRequest = new Promise((resolve) => {
            setTimeout(() => {
              resolve();
            }, 1000);
          });
          return delayRetryRequest.then(() => axios(originalRequest));
        }

        throw error;
      };

      api.interceptors.response.use(
        (response ) => response,
        (error) => retryRequest(error),
      );
    }

    const response = await api
      .get(url, options);
    const { headers, data } = response;
    return { headers, data };
  } catch (error) {
    console.log(JSON.stringify(error, null, 2))
    const {
      status,
      data,
    } = error.response;
    throw new Error(data);
  }
}
