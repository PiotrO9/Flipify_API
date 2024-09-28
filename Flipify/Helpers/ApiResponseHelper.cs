using Flipify.Models;

namespace Flipify.Helpers
{
    public static class ApiResponseHelper
    {
        public static ApiResponse<T> CreateSuccessResponse<T>(T data, string message = "Operation successful", int statusCode = 200)
        {
            return new ApiResponse<T>(true, message, data, statusCode);
        }

        public static ApiResponse<T> CreateErrorResponse<T>(string message, int statusCode)
        {
            return new ApiResponse<T>(false, message, default, statusCode);
        }
    }

}
