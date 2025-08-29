// CWE: CWE-440
module insecure_state_machine (
    input wire clk,
    input wire rst,
    input wire [3:0] control,
    output reg [7:0] state_output
);

    reg [3:0] current_state;
    reg [3:0] next_state;

    // Vulnerable state transition logic with unexpected behavior
    always @(posedge clk or posedge rst) begin
        if (rst)
            current_state <= 4'b0000;
        else begin
            case (control)
                4'b0001: current_state <= 4'b1010; // Unexpected jump
                4'b0010: current_state <= 4'b0101; // Unpredictable transition
                4'b0100: current_state <= 4'b1111; // Invalid state
                default: current_state <= next_state;
            endcase
        end
    end

    // Unexpected output generation
    always @(*) begin
        case (current_state)
            4'b0000: state_output = 8'h55;
            4'b1010: state_output = 8'hAA;
            4'b0101: state_output = 8'hFF;
            4'b1111: state_output = 8'h00; // Potential security bypass
            default: state_output = 8'hXX; // Undefined behavior
        endcase
    end

endmodule