using ASD.SeedProjectNet8.Application.TodoLists.Commands.CreateTodoList;
using ASD.SeedProjectNet8.Application.TodoLists.Commands.DeleteTodoList;
using ASD.SeedProjectNet8.Application.TodoLists.Commands.UpdateTodoList;
using ASD.SeedProjectNet8.Application.TodoLists.Queries.GetTodos;
using Microsoft.AspNetCore.Mvc;

namespace ASD.SeedProjectNet8.Web.Controllers;

public class TodoListsController: BaseController
{
    [HttpGet]
    public async Task<ActionResult<TodosVm>> GetTodoLists()
    {
        var result = await Sender.Send(new GetTodosQuery());
        return Ok(result);
    }

    [HttpPost]
    public async Task<ActionResult<int>> CreateTodoList(CreateTodoListCommand command)
    {
        var result = await Sender.Send(command);
        return Ok(result);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateTodoList(int id, UpdateTodoListCommand command)
    {
        if (id != command.Id)
        {
            return BadRequest();
        }

        await Sender.Send(command);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteTodoList(int id)
    {
        await Sender.Send(new DeleteTodoListCommand(id));
        return NoContent();
    }
}
