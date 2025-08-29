// CWE: CWE-440
module counter_with_reset(clk, rst, count);
    input clk;
    input rst;
    output reg [3:0] count;

    always @(posedge clk) begin
        if (rst)
            count <= 4'b0000;
        else
            count <= count + 1;
    end

    // Expected behavior violation: count should reset to 4'b0000 when it reaches 4'b1111
    // but it continues incrementing.
endmodule