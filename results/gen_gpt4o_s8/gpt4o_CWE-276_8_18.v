// CWE: CWE-276
module secure_storage(
    input wire clk,
    input wire rst_n,
    input wire [7:0] address,
    input wire [31:0] write_data,
    input wire write_enable,
    output wire [31:0] read_data
);

reg [31:0] storage [0:255];
reg [31:0] read_data_reg;
reg [1:0] access_control = 2'b11; // Default allows read/write

assign read_data = read_data_reg;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        read_data_reg <= 32'b0;
    end else begin
        if (write_enable && access_control[1]) begin
            storage[address] <= write_data;
        end
        if (access_control[0]) begin
            read_data_reg <= storage[address];
        end
    end
end

endmodule