namespace ASD.SeedProjectNet8.Application.Common.Models;

// Base non-generic Result class (similar to your original)
public class Result
{
    protected Result(bool succeeded, IEnumerable<string> errors)
    {
        Succeeded = succeeded;
        Errors = errors.ToArray();
    }

    public bool Succeeded { get; }
    public string[] Errors { get; }
    public bool Failed => !Succeeded;

    public static Result Success()
    {
        return new Result(true, []);
    }

    public static Result Failure(IEnumerable<string> errors)
    {
        return new Result(false, errors);
    }

    public static Result Failure(string error)
    {
        return new Result(false, [error]);
    }
}

// Generic Result<T> as a separate class (not inheriting from Result)
public class Result<T>
{
    private readonly T? _value;

    private Result(T? value, bool succeeded, IEnumerable<string> errors)
    {
        _value = value;
        Succeeded = succeeded;
        Errors = errors.ToArray();
    }

    public bool Succeeded { get; }
    public string[] Errors { get; }
    public bool Failed => !Succeeded;

    // Value is only accessible if the result succeeded
    public T Value => Succeeded
        ? _value!
        : throw new InvalidOperationException($"Cannot access Value on failed result. Errors: {string.Join(", ", Errors)}");

    // Factory methods for creating success results with values
    public static Result<T> Success(T value)
    {
        return new Result<T>(value, true, Array.Empty<string>());
    }

    // Factory methods for creating failure results
    public static Result<T> Failure(IEnumerable<string> errors)
    {
        return new Result<T>(default, false, errors);
    }

    public static Result<T> Failure(string error)
    {
        return new Result<T>(default, false, new[] { error });
    }

    // Convert to non-generic result (loses the value)
    public Result ToResult()
    {
        return Succeeded
            ? Result.Success()
            : Result.Failure(Errors);
    }
}

// Extension methods for working with Results
public static class ResultExtensions
{
    // Map success value to a new value
    public static Result<TOut> Map<TIn, TOut>(this Result<TIn> result, Func<TIn, TOut> mapper)
    {
        return result.Succeeded
            ? Result<TOut>.Success(mapper(result.Value))
            : Result<TOut>.Failure(result.Errors);
    }

    // Bind to another result-returning function (monadic bind)
    public static Result<TOut> Bind<TIn, TOut>(this Result<TIn> result, Func<TIn, Result<TOut>> binder)
    {
        return result.Succeeded
            ? binder(result.Value)
            : Result<TOut>.Failure(result.Errors);
    }

    // Try/catch wrapper for operations that might throw
    public static Result<T> Try<T>(Func<T> func, Func<Exception, string>? errorHandler = null)
    {
        try
        {
            return Result<T>.Success(func());
        }
        catch (Exception ex)
        {
            var errorMessage = errorHandler != null
                ? errorHandler(ex)
                : ex.Message;

            return Result<T>.Failure(errorMessage);
        }
    }

    // Match pattern (like pattern matching) for handling both cases
    public static TOut Match<T, TOut>(this Result<T> result, Func<T, TOut> onSuccess, Func<string[], TOut> onFailure)
    {
        return result.Succeeded
            ? onSuccess(result.Value)
            : onFailure(result.Errors);
    }

    // Ensure a condition is met, or return a failure
    public static Result<T> Ensure<T>(this Result<T> result, Func<T, bool> predicate, string errorMessage)
    {
        if (!result.Succeeded)
            return result;

        return predicate(result.Value)
            ? result
            : Result<T>.Failure(errorMessage);
    }
}
