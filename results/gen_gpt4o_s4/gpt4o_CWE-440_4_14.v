// CWE: CWE-440
module faulty_counter(clk, rst, enable, count);
    input clk;
    input rst;
    input enable;
    output reg [3:0] count;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            count <= 4'b0000;
        end else if (enable) begin
            if (count == 4'b1111) begin
                count <= 4'b0000; // Expected behavior: reset to zero
            end else begin
                count <= count + 1;
            end
        end
    end

    // Faulty behavior: incorrect reset condition
    always @(posedge clk) begin
        if (count == 4'b1010) begin
            count <= 4'b0000; // Unexpected reset at 10
        end
    end
endmodule