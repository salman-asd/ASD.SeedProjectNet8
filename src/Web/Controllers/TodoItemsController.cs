using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.TodoItems.Commands.CreateTodoItem;
using ASD.SeedProjectNet8.Application.TodoItems.Commands.DeleteTodoItem;
using ASD.SeedProjectNet8.Application.TodoItems.Commands.UpdateTodoItem;
using ASD.SeedProjectNet8.Application.TodoItems.Commands.UpdateTodoItemDetail;
using ASD.SeedProjectNet8.Application.TodoItems.Queries.GetTodoItemsWithPagination;
using Microsoft.AspNetCore.Mvc;

namespace ASD.SeedProjectNet8.Web.Controllers;

public class TodoItemsController: BaseController
{
    [HttpGet]
    public async Task<ActionResult<PaginatedList<TodoItemBriefDto>>> GetTodoItemsWithPagination([FromQuery] GetTodoItemsWithPaginationQuery query)
    {
        var result = await Sender.Send(query);
        return Ok(result);
    }

    [HttpPost]
    public async Task<ActionResult<int>> CreateTodoItem(CreateTodoItemCommand command)
    {
        var result = await Sender.Send(command);
        return Ok(result);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateTodoItem(int id, UpdateTodoItemCommand command)
    {
        if (id != command.Id)
        {
            return BadRequest();
        }

        await Sender.Send(command);
        return NoContent();
    }

    [HttpPut("UpdateDetail/{id}")]
    public async Task<IActionResult> UpdateTodoItemDetail(int id, UpdateTodoItemDetailCommand command)
    {
        if (id != command.Id)
        {
            return BadRequest();
        }

        await Sender.Send(command);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteTodoItem(int id)
    {
        await Sender.Send(new DeleteTodoItemCommand(id));
        return NoContent();
    }
}
